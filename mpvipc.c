#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/select.h>

#define BUFSIZE 10240
// S(x) expands x as string
#define _S(x) #x
#define S(x) _S(x)


//
// misc helpers
//

// debug output
static int debug_flag = 0;
void debug(const char *format, ...)
{
  if(!debug_flag) return;

  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}


int    max_fd = 0;   // max file descriptor we have seen
fd_set empty_fd_set; // to be initialized to 'zero' in main
// select helper - check if the given file descriptor set is empty
int FD_IS_EMPTY(fd_set* fdset) {
  return memcmp(fdset, &empty_fd_set, sizeof(fd_set)) == 0;
}

// socket helper - returns fd for given path
int open_fd(char* path)
{
  int fd;
  struct sockaddr_un addr;

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    debug("socket error  : %s - %s\n", path, strerror(errno));
    return 0;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    debug("connect error : %s - %s\n", path, strerror(errno));
    if(errno == ECONNREFUSED)
      // stale socket from an mpv process that probably died
      unlink(path);
    return 0;
  }

  return fd;
}


//
// mpv client data, realized as linked list, and helper functions
//

// request type, so we can store the response in the appropriate struct client
// field
typedef enum
{
 normal,
 title
} reqtype_t;

// client structure - we store file descriptor, response and optionally title
struct client
{
  int fd;
  char title[BUFSIZE+1];
  char response[BUFSIZE+1];
  struct client *next;
};
// global mpv client linked list
struct client *clist = NULL;

// add a descriptor to linked list
void clist_add_fd(int fd) {

  struct client *cl      = clist;
  struct client *cl_prev = cl;

  // check if fd is already part of the list
  while(cl) {
    if(cl->fd == fd)
      // found
      return;
    cl_prev = cl;
    cl = cl->next;
  }
  // either clist is emtpy or cl_prev is now the last element of the list

  // create new struct element
  cl = malloc(sizeof(struct client));
  memset(cl, 0, sizeof(struct client));
  cl->fd = fd;

  if(cl_prev)
    // clist wasn't empty
    cl_prev->next = cl;
  else
    // clist was empty - first element
    clist = cl;

  // update max fd we have seen
  max_fd = max_fd > fd ? max_fd : fd;
  return;
}

// return pointer to client struct for given fd, or NULL
struct client* clist_find_cl(int fd){

  struct client *cl = clist;
  while(cl) {
    if(cl->fd == fd)
      return cl;
    cl = cl->next;
  }
  return NULL;
}

// print data of entire list
void clist_print_all() {

  struct client *cl = clist;
  while(cl) {
    if(cl->title[0])
      printf("%s", cl->title);
    if(cl->response[0])
      printf("%s", cl->response);
    cl = cl->next;
  }
}

// close all file descriptors we have got
void clist_close_all() {

  struct client *cl = clist, *cl_tmp;
  while(cl) {
    if(cl->fd) {
      debug("fd %2d - close :\n", cl->fd);
      close(cl->fd);
    }
    cl_tmp = cl->next;
    free(cl);
    cl = cl_tmp;
  }
}

// the core communication function - sends cmd to all clients and collects
// responses
void clist_get_response(char* cmd, reqtype_t rtype) {

  int  retval = 0, read_empty = 0, write_empty = 0;
  ssize_t nread = 0, nwritten = 0;
  char buf[BUFSIZE+1];
  struct client *cl = clist;
  struct timeval tv, tv_default;
  fd_set active_read_fd_set, read_fd_set, active_write_fd_set, write_fd_set;
  fd_set *read_fd_set_ptr, *write_fd_set_ptr;

  // obviously, if clist is empty we got nothing to do
  if(!cl) return;

  // select timeout, half second
  tv_default.tv_sec  = 1;
  tv_default.tv_usec = 0;

  FD_ZERO (&active_read_fd_set);
  FD_ZERO (&active_write_fd_set);

  // walk through list and as fd's to read/write sets for select
  while(cl) {
    FD_SET (cl->fd, &active_read_fd_set);
    FD_SET (cl->fd, &active_write_fd_set);
    cl = cl->next;
  }

  // only when sending commands in JSON format we need to read a response
  if(!strstr(cmd, "\"command\"")) FD_ZERO (&active_read_fd_set);
  read_empty  = FD_IS_EMPTY(&active_read_fd_set);
  write_empty = FD_IS_EMPTY(&active_write_fd_set);

  // we remove read/write fd's from active sets as we go along - quit loop when
  // both are empty
  while(!(read_empty && write_empty)) {

    if(read_empty)
      read_fd_set_ptr = NULL;
    else {
      memcpy(&read_fd_set, &active_read_fd_set, sizeof(fd_set));
      read_fd_set_ptr = &read_fd_set;
    }

    if(write_empty)
      write_fd_set_ptr = NULL;
    else {
      memcpy(&write_fd_set, &active_write_fd_set, sizeof(fd_set));
      write_fd_set_ptr = &write_fd_set;
    }

    // note: select might modify tv
    memcpy(&tv, &tv_default, sizeof(struct timeval));
    retval = select(max_fd + 1, read_fd_set_ptr, write_fd_set_ptr, NULL, &tv);
    debug("time          : %ld.%03ld\n", (long) tv.tv_sec, (long) tv.tv_usec/1000);

    if (retval < 0) {
      debug("select error: %s\n", strerror(errno));
      return;
    }
    else if (retval == 0) {
      debug("select timeout\n");
      return;
    }

    // now iterate over the whole [0, max_fd] range and see if an fd is
    // readable and/or writable
    for (int fd = 0; fd <= max_fd; ++fd) {

      // check if writable
      if (!write_empty && FD_ISSET (fd, &write_fd_set)) {

        snprintf(buf, BUFSIZE, "%s\n", cmd);
        debug("fd %2d - write : %s", fd, buf);

        nwritten = write(fd, buf, strlen(buf));
        if(nwritten <= 0) {
          if(nwritten < 0)
            debug("write error : %s\n", strerror(errno));
          else
            debug("write error : 0 written - %s\n", strerror(errno));
          FD_CLR (fd, &active_write_fd_set);
          continue;
        }

        // delete fd from write set
        FD_CLR (fd, &active_write_fd_set);
      }

      // check if readable
      if (!read_empty && FD_ISSET (fd, &read_fd_set)) {

        nread = read(fd,buf,BUFSIZE);
        if(nread <= 0) {
          if(nread < 0)
            debug("read error  : %s\n", strerror(errno));
          else
            debug("read error  : 0 read - %s\n", strerror(errno));
          FD_CLR (fd, &active_read_fd_set);
          continue;
        }
        buf[nread] = '\0';
        debug("fd %2d - read  : %s", fd, buf);

        // only response lines matching this are valid for us
        if(strstr(buf, ",\"error\":\"")) {

          // find client data in linked list for given fd
          cl = clist_find_cl(fd);
          if (cl) {
            // store response according to request type
            if(rtype == title) {
              sscanf(buf, "%" S(BUFSIZE) "c", cl->title);
            }
            else {
              sscanf(buf, "%" S(BUFSIZE) "c", cl->response);
            }
          }
          // since the response was valid delete fd from read list
          FD_CLR (fd, &active_read_fd_set);
        }
      }
    } // end for loop

    // update empty statuses after FD_CLR calls and before next while iteration
    write_empty = write_empty || FD_IS_EMPTY(&active_write_fd_set);
    read_empty  = read_empty  || FD_IS_EMPTY(&active_read_fd_set);

  } // end while loop
}


//
// main
//

int main (int argc, char **argv)
{
  // command line option parsing
  int   c       = 0;
  int   verbose = 0;
  char* exclude = NULL;
  char* include = NULL;

  while (1) {
    static struct option long_options[] =
      {
       // default is to operate on the sockets of all running mpv instances;
       // exclude/include modify this behavior
       //
       // extra verbose output to stderr
       {"debug",   no_argument,       0, 'd'},
       // operate on all other sockets except this one
       {"exclude", required_argument, 0, 'e'},
       // operate only on this socket
       {"include", required_argument, 0, 'i'},
       // print responses
       {"verbose", no_argument,       0, 'v'},
       {0, 0, 0, 0}
      };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "de:i:v", long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1) break;

    switch (c) {
    case 'd':
      debug_flag = 1;
      break;
    case 'e':
      // e means: we perform command on all sockets, just not this one
      exclude = optarg;
      break;
    case 'i':
      // i means: we perform command only on this socket
      include = optarg;
      break;
    case 'v':
      // print responses
      verbose = 1;
      break;
    case '?':
      /* getopt_long already printed an error message. */
      break;
    default:
      abort ();
    }
  }

  if(debug_flag) debug("debug         : enabled\n");
  if(verbose)    debug("verbose       : enabled\n");
  if(exclude)    debug("exclude       : %s\n", exclude);
  if(include)    debug("include       : %s\n", include);

  // after option parsing, there should be the actual mpv command
  if (optind >= argc) {
    debug("No command given, exiting.\n");
    exit(0);
  }

  // socket directory
  char* dir = "/home/ghermann/.config/mpv/socket";
  int   fd;
  char  buf[BUFSIZE+1];
  // directory traversal
  DIR*  dp;
  struct dirent *ep;
  // stat
  struct stat    sb;

  // now go over socket directory entries and construct linked list
  dp = opendir(dir);
  if (dp != NULL) {

    while ((ep = readdir (dp))) {

      // construct full path of directory entry
      snprintf(buf, BUFSIZE, "%s/%s", dir, ep->d_name);

      // see if directory entry is a socket - if not, proceed to next one
      if ( (stat(buf, &sb) == -1) || ((sb.st_mode & S_IFMT) != S_IFSOCK))
        continue;

      // skip if this pid excluded
      if (exclude && (strcmp(exclude, ep->d_name) == 0))
        continue;

        // if include is set that's all we want
      if(include) {

        if(strcmp(include, ep->d_name) == 0) {
          // get file descriptor and add it to linked list
          fd = open_fd(buf);
          if (fd) clist_add_fd(fd);
          debug("fd %2d - path  : %s\n", fd, buf);
          // done - we want just this one entry
          break;
        }
        continue;
      }

      fd = open_fd(buf);
      if (fd) clist_add_fd(fd);
      debug("fd %2d - path  : %s\n", fd, buf);
    }

    // directory traversal finished, linked list complete
    (void) closedir(dp);
  }
  else {
    debug("directory traversal error: %s\n", strerror(errno));
    exit(1);
  }

  if(!clist) {
    debug("fd set emtpy, exiting.\n");
    exit(0);
  }


  // initialize this global before calls to clist_get_response; we need it to
  // recognize if an fd_set is empty
  FD_ZERO(&empty_fd_set);

  // optionally get titles
  if(verbose) clist_get_response("{ \"command\": [\"get_property\", \"media-title\"] }", title);

  char* cmd = NULL;
  while (optind < argc) {
    cmd = argv[optind++];
    clist_get_response(cmd, normal);
    if(verbose) clist_print_all();
  }

  clist_close_all();

  exit (0);
}
