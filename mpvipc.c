/*
  mpvipc - send IPC commands to one mpv instance or multiple of them

  Usage examples:
  mpvipc -v '{ "command": ["get_property", "track-list"] }'
  mpvipc '{ "command": ["cycle-values", "osd-level", "2", "3", "1"] }'
  mpvipc 'show-text ${media-title} 10000'

  This assumes a well defined directory where the sockets of all running mpv
  instances can be found. The default value is $HOME/.config/mpv/socket but it
  can be modified by command line option. Myself, I always run mpv through a
  script wrapper to ensure consistent behavior.

  Another example, lua code:
  function on_mute_change(name, value)
  if value == false then
    local socket = mp.get_property('input-ipc-server')
    local cmd = [[{ "command": ["set_property", "mute", true] }]]
    if socket ~= '' then
      os.execute(("mpvipc -e %s %q"):format(socket, cmd))
    end
  end
  end
  mp.observe_property("mute", "bool", on_mute_change)

  This way, each time an instance is un-muted all other instances are muted.
  Obviously useful when you don't appreciate multiple instances babbling at the
  same time.

  Other usage examples are mpv key bindings that control all running mpv
  instances at the same time. Like an Alt+q binding to quit them all. Or at-jobs
  to start/stop recordings.

  Options:
  -v verbose - the program is written to produce zero output per default
  -d debug   - extra diagnostics regarding IPC communication and socket polling
  -e exclude - exclude this socket from operation; basename or full path
  -i include - the opposite; operate on this socket only; basename or full path
  -p path    - path to socket directory; absolute or relative to HOME

  Compile like this:
  clang mpvipc.c -o mpvipc
  or with gdb if you like, same options.

 */

#define _GNU_SOURCE
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
#include <poll.h>

#define BUFSIZE 10240
// S(x) expands x as string
#define _S(x) #x
#define S(x) _S(x)


// number of file descriptors we need to poll
int num_fds = 0;


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

// check if a bit is set, return 1 if so, else 0
int bit(short event, unsigned short mask) {
  return event & mask? 1:0;
}

// unix domain socket helper - returns fd for given path
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

  struct client *cl = clist, *cl_prev = cl;

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

  return;
}

// print data of clist array
void clist_print_all() {

  struct client *cl = clist;
  for(int i=0; i<num_fds; i++, cl++) {
    if(cl->title[0])
      printf("%s", cl->title);
    if(cl->response[0])
      printf("%s", cl->response);
  }
}

// close all file descriptors we have got
void clist_close_all() {

  struct client *cl = clist;
  for(int i=0; i<num_fds; i++, cl++) {
    if(cl->fd) {
      debug("fd %2d - close :\n", cl->fd);
      close(cl->fd);
    }
  }
}

// the core communication function - sends cmd to all clients and collects
// responses
void clist_get_response(char* cmd, reqtype_t rtype) {

  int  retval = 0, num_finished = 0, fd;
  ssize_t nread = 0, nwritten = 0;
  short events;
  unsigned short poll_read = POLLIN, poll_write = POLLOUT;
  unsigned short poll_all = POLLIN | POLLPRI | POLLOUT
#if defined __USE_XOPEN || defined __USE_XOPEN2K8
    | POLLRDNORM | POLLRDBAND
#endif
#ifdef __USE_GNU
    | POLLMSG | POLLREMOVE | POLLRDHUP
#endif
    ;
  char buf[BUFSIZE+1];
  struct client *cl = clist;

  // obviously, if clist is empty we got nothing to do
  if(!cl) return;

  // array of polling structures
  struct pollfd *fds = calloc(num_fds, sizeof(struct pollfd)), *fds_tmp = fds;

  // initialize fd's and event flags
  for(int i=0; i<num_fds; i++, fds_tmp++) {

    fds_tmp->fd = (clist+i)->fd;

    if(debug_flag)
      // let's see what else might be going on in debug mode
      fds_tmp->events = poll_all;
    else if(strstr(cmd, "\"command\""))
      // json, need to read response
      fds_tmp->events = poll_read | poll_write;
    else
      // plain command, there won't be a response
     fds_tmp->events = poll_write;
  }

  // main polling loop - keep going til we have seen 1 read/write each on all
  // fd's
  while(num_finished < num_fds) {

    // 1 second timeout
    retval = poll(fds, (nfds_t) num_fds, 1000);
    if (retval < 0) {
      debug("poll error  : %s\n", strerror(errno));
      return;
    }
    else if (retval == 0) {
      debug("poll timeout\n");
      return;
    }

    // now iterate over the [0, num_fds] range and see if an fd is readable
    // and/or writable
    fds_tmp = fds;
    for (int i = 0; i < num_fds; i++, fds_tmp++) {

      fd = fds_tmp->fd;
      // already done on this fd
      if(fd == -1) continue;

      events = fds_tmp->revents;
      if(events != 0)
        debug("fd %2d revents :%d %d %d %d %d %d %d %d\n"
              ,fd
              ,bit(events, POLLIN)
              ,bit(events, POLLPRI)
              ,bit(events, POLLOUT)
#if defined __USE_XOPEN || defined __USE_XOPEN2K8
              ,bit(events, POLLRDNORM)
              ,bit(events, POLLRDBAND)
#else
              ,0
              ,0
#endif
#ifdef __USE_GNU
              ,bit(events, POLLMSG)
              ,bit(events, POLLREMOVE)
              ,bit(events, POLLRDHUP)
#else
              ,0
              ,0
              ,0
#endif
              );

      // check if writable
      if (fds_tmp->revents & poll_write) {

        snprintf(buf, BUFSIZE, "%s\n", cmd);
        debug("fd %2d - write : %s", fd, buf);

        nwritten = write(fd, buf, strlen(buf));
        if(nwritten <= 0) {
          if(nwritten < 0)
            debug("write error : %s\n", strerror(errno));
          else
            debug("write error : 0 written - %s\n", strerror(errno));
          continue;
        }

        // done polling for writes on this fd
        fds_tmp->events &= ~poll_write;
      }

      // check if readable
      if (fds_tmp->revents & poll_read) {

        nread = read(fd,buf,BUFSIZE);
        if(nread <= 0) {
          if(nread < 0)
            debug("read error  : %s\n", strerror(errno));
          else
            // eof
            debug("read error  : 0 read - %s\n", strerror(errno));
          // done polling for reads on this fd
          fds_tmp->events &= ~poll_read;
          continue;
        }

        buf[nread] = '\0';
        debug("fd %2d - read  : %s", fd, buf);

        // only response lines matching this are valid for us
        if(strstr(buf, ",\"error\":\"")) {

          // client struct for given fd
          cl = clist + i;
          // store response according to request type
          if(rtype == title) {
            sscanf(buf, "%" S(BUFSIZE) "c", cl->title);
          }
          else {
            sscanf(buf, "%" S(BUFSIZE) "c", cl->response);
          }

          // done polling for reads on this fd
          fds_tmp->events &= ~poll_read;
        }
      }

      // if an fd has seen both, one read and one write, it doesn't need any
      // more polling
      if( (fds_tmp->events & (poll_read|poll_write)) == 0) {
        fds_tmp->fd = -1;
        num_finished++;
      }
    } // end for loop
  } // end while loop

  free(fds);
}


//
// main
//

int main (int argc, char **argv)
{
  // command line option parsing
  int   c       = 0;
  int   verbose = 0;
  char* exclude = NULL, *include = NULL, *path = NULL, *home = NULL;

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
       // path to socket dir - can be absolute or relative to HOME
       {"path",    required_argument, 0, 'p'},
       // print responses
       {"verbose", no_argument,       0, 'v'},
       {0, 0, 0, 0}
      };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "de:i:vp:", long_options, &option_index);

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
    case 'p':
      path = optarg;
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
  if(path)       debug("path          : %s\n", path);

  // after option parsing, there should be the actual mpv command
  if (optind >= argc) {
    fprintf(stderr, "No command given, exiting.\n");
    exit(1);
  }

  // socket directory
  char *dir = NULL;
  // stat
  struct stat sb;

  home = getenv("HOME");
  // the default I use in my home dir
  if(!path) path = ".config/mpv/socket";

  if(path[0] != '/' && !home) {
    fprintf(stderr, "socket directory path relative and HOME not set: %s\n", path);
    fprintf(stderr, "exiting.\n");
    exit(1);
  }
  else if(path[0] == '/')
    dir = path;
  else {
    int len = strlen(home) + strlen(path) + 2;
    dir = malloc(len);
    snprintf(dir, len, "%s/%s", home, path);
  }
  if ( (stat(dir, &sb) == -1) || ((sb.st_mode & S_IFMT) != S_IFDIR)) {
    fprintf(stderr, "socket directory doesn't exist: %s\n", dir);
    fprintf(stderr, "exiting.\n");
    exit(1);
  }
  debug("socket dir    : %s\n", dir);

  int   fd;
  char  buf[BUFSIZE+1];
  // directory listing
  DIR*  dp;
  struct dirent *ep;

  // now go over socket directory entries and construct linked list
  dp = opendir(dir);
  if (dp != NULL) {

    while ((ep = readdir (dp))) {

      // construct full path of directory entry
      snprintf(buf, BUFSIZE, "%s/%s", dir, ep->d_name);

      // see if directory entry is a socket - if not, proceed to next one
      if ( (stat(buf, &sb) == -1) || ((sb.st_mode & S_IFMT) != S_IFSOCK))
        continue;

      // skip if this socket is excluded; can be basename or full path
      if (exclude &&
          ((strcmp(exclude, ep->d_name) == 0) || (strcmp(exclude, buf) == 0)))
        continue;

      // if include is set that's the only (!) socket we want
      if(include) {

        if ((strcmp(include, ep->d_name) == 0) || (strcmp(include, buf) == 0)) {
          // get file descriptor and add it to linked list
          fd = open_fd(buf);
          if (fd) {
            clist_add_fd(fd);
            num_fds++;
          }
          debug("fd %2d - path  : %s\n", fd, buf);
          // done
          break;
        }
        continue;
      }

      // we get here only when include isn't set, and when this path is not
      // excluded
      fd = open_fd(buf);
      if (fd) {
        clist_add_fd(fd);
        num_fds++;
      }
      debug("fd %2d - path  : %s\n", fd, buf);
    }

    // directory listing finished, linked list complete
    (void) closedir(dp);
  }
  else {
    fprintf(stderr, "directory listing error: %s\n", strerror(errno));
    fprintf(stderr, "for directory: %s\nexiting.\n", dir);
    exit(1);
  }
  if(dir && dir != path) free(dir);

  if(!clist) {
    fprintf(stderr, "socket set emtpy, exiting.\n");
    exit(0);
  }

  // turn linked list into array, for easier use; not strictly necessary, but
  // this way we don't need to advance two structurally different pointers
  // (clist, fds) each time we do a continue on a loop, but can rely on
  // identical offsets for both instead
  struct client *cl_arr = malloc(num_fds * sizeof(struct client)), *cl_ptr = cl_arr, *cl_tmp = NULL;
  while(clist) {
    memcpy(cl_ptr++, clist, sizeof(struct client));
    cl_tmp = clist;
    clist = clist->next;
    free(cl_tmp);
  }
  clist = cl_arr;

  // optionally get titles
  if(verbose) clist_get_response("{ \"command\": [\"get_property\", \"media-title\"] }", title);

  char* cmd = NULL;
  while (optind < argc) {
    cmd = argv[optind++];
    clist_get_response(cmd, normal);
    if(verbose) clist_print_all();
  }

  clist_close_all();
  free(clist);

  exit (0);
}
