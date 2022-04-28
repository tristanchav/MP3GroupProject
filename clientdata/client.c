/******************************************************************************

PROGRAM:  client.c
AUTHOR:   Tristan Chavez, Nhi La, Wega Kinoti
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: An authentication machine that then prompts for and copies/plays an MP3 file from the server

******************************************************************************/
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <time.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

#include "SDL2/SDL.h"
#include "SDL2/SDL_mixer.h"
#include <dirent.h>

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define PASSWORD_LENGTH     32
#define SEED_LENGTH         8
#define PATHLENGTH          256
#define SENTINAL            -1


#define ERR_TOO_FEW_ARGS  1
#define ERR_TOO_MANY_ARGS 2
#define ERR_INVALID_OP    3
/******************************************************************************

This function does the basic necessary housekeeping to establish a secure TCP
connection to the server specified by 'hostname'.

*******************************************************************************/
int create_socket(char* hostname, unsigned int port)
{
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL)
    {
      fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
      exit(EXIT_FAILURE);
    }
  
  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  
  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  
  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) <0)
    {
      fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	      hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
      exit(EXIT_FAILURE);
    }

  return sockfd;
}

void getPassword(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Hide, i.e., turn off echoing, the characters typed to the console
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < BUFFER_SIZE)
      password[i++] = c;

    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
}

int main(int argc, char** argv)
{
  const SSL_METHOD* method;
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              filename[PATHLENGTH] = {0};
  char              buffer[BUFFER_SIZE] = {0};
  char*             temp_ptr;
  int               sockfd;
  int               writefd;
  int               rcount;
  int               wcount;
  int               error_code;
  int               total = 0;
  SSL_CTX*          ssl_ctx;
  SSL*              ssl;
  char              confirm[BUFFER_SIZE];

  char	            response[BUFFER_SIZE];
  char	            logInResponse[BUFFER_SIZE];
  char	            password[PASSWORD_LENGTH];
  char	            username[BUFFER_SIZE];
  char              message[BUFFER_SIZE];
  char              session[BUFFER_SIZE] = "null";
  char              bf[128];                 // Used to read the entire 128-byte ID3 tag
  char              title[31];               // 30-byte title field from the ID3 tag
  char              artist[31];              // 30-byte artist field from the ID3 tag
  char              album[31];               // 30-byte album field from the ID3 tag
  char              year[5];                 // 4-byte year field from the ID3 tag
  int               flags  = MIX_INIT_MP3;   // Mix_Init initializer flags for MP3 files
  int               result;
  int               fd;
  
  if (argc != 2)
    {
      fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
      exit(EXIT_FAILURE);
    }
  else
    {
      // Search for ':' in the argument to see if port is specified
      temp_ptr = strchr(argv[1], ':');
      if (temp_ptr == NULL)    // Hostname only. Use default port
	  strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
      else
	{
	  // Argument is formatted as <hostname>:<port>. Need to separate
	  // First, split out the hostname from port, delineated with a colon
	  // remote_host will have the <hostname> substring
	  strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
	  // Port number will be the substring after the ':'. At this point
	  // temp is a pointer to the array element containing the ':'
	  port = (unsigned int) atoi(temp_ptr+sizeof(char));
	}
    }
  
  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if(SSL_library_init() < 0)
    {
      fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
      exit(EXIT_FAILURE);
    }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL)
    {
      fprintf(stderr, "Unable to create a new SSL context structure.\n");
      exit(EXIT_FAILURE);
    }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

  // Create a new SSL connection state object                     
  ssl = SSL_new(ssl_ctx);

  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }

  // Bind the SSL object to the network socket descriptor.  The socket descriptor
  // will be used by OpenSSL to communicate with a server. This function should only
  // be called once the TCP connection is established, i.e., after create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection.  SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    fprintf(stdout, "Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }
  
  char x, y;
  while(strncmp(response, "CANCEL", 6) != 0) {
    fprintf(stdout, "Client: Please indicate if you want to SIGNIN, CREATE an account or CANCEL\n");
    fgets(response, BUFFER_SIZE-1, stdin);

    // Code for an existing user to sign in
    if (strncmp(response, "SIGNIN", 6) == 0) {
      fprintf(stdout, "Client: Please enter your username\n");
      fgets(buffer, BUFFER_SIZE-1, stdin);
      sscanf(buffer, "%s", &x);
      strncpy(username, &x, BUFFER_SIZE);
      
      fprintf(stdout, "Client: Please enter your password\n");
      getPassword(password);
      //fprintf(stdout, "%s\n", password); debug
      
      snprintf(message, BUFFER_SIZE*3, "SIGNIN %s %s", username, password);
      //fprintf(stdout, "%s\n", message); debug
      wcount = SSL_write(ssl, message, BUFFER_SIZE);
      rcount = SSL_read(ssl, session, BUFFER_SIZE);
      if (strncmp(session, "ERROR: SIGNINWRONG", 18) == 0) {
        fprintf(stderr, "Client: ERROR: No user found\n");
        strncpy(session, "null", BUFFER_SIZE);
      }
      else if (strncmp(session, "ERROR:", 6) == 0) {
        fprintf(stderr, "Client: %s\n", session);
        strncpy(session, "null", BUFFER_SIZE);
      }
      //fprintf(stdout, "%s\n", session); debug
      bzero(buffer, BUFFER_SIZE);
    }

    // Code to create a new user
    else if (strncmp(response, "CREATE", 6) == 0) {
      fprintf(stdout, "Client: Please enter your new username\n");
      fgets(buffer, BUFFER_SIZE-1, stdin);
      sscanf(buffer, "%s", &x);
      strncpy(username, &x, BUFFER_SIZE);
      bzero(buffer, BUFFER_SIZE);

      fprintf(stdout, "Client: Please enter your new password\n");
      getPassword(password);
      //fprintf(stdout, "%s\n", password); debug

      //Special strings "ERROR:" and "null" would potentially cause error checking problems if used as a name
      if ((strncmp(username, "null", 4) != 0) && (strncmp(username, "ERROR:", 6) != 0)) {
        snprintf(message, BUFFER_SIZE*3, "CREATE %s %s", username, password);
        //fprintf(stdout, "%s\n", message); debug
        wcount = SSL_write(ssl, message, BUFFER_SIZE);
        rcount = SSL_read(ssl, session, BUFFER_SIZE);
        if (strncmp(session, "ERROR: TAKEN", 12) == 0) {
          fprintf(stderr, "Client: ERROR: Username or password already taken\n");
          strncpy(session, "null", BUFFER_SIZE);
        }
        else if (strncmp(session, "ERROR:", 6) == 0) {
          fprintf(stderr, "Client: %s\n", session);
          strncpy(session, "null", BUFFER_SIZE);
        }
        else {
          strncpy(session, "null", BUFFER_SIZE);
        }
      }
      else {
        fprintf(stdout, "Client: Please do not use \"null\" or \":\" in your username\n");
      }
      //fprintf(stdout, "%s\n", session); debug
      bzero(buffer, BUFFER_SIZE);
    }
    
    else if (strncmp(response, "CANCEL", 6) == 0) {
      wcount = SSL_write(ssl, "CANCEL", 6);
    }

    else {
      fprintf(stdout, "Client: Unknown input, please type in SIGNIN, CREATE or CANCEL\n");
    }

    //Once a user is logged in they can access this
    if(strncmp(session, "null", 4) != 0) {
      wcount = SSL_write(ssl, "LOGGED IN", 9);
      fprintf(stdout, "Client: Logged in as %s\n", session);
  //**************************File Request and some directory*****************************************
  fprintf(stdout, "Enter file name: ");
  fgets(filename, PATHLENGTH, stdin);
  filename[strlen(filename)-1] = '\0';

  // Marshal the parameter into an RPC message
  sprintf(buffer, "download %s", filename);
  SSL_write(ssl, buffer, strlen(buffer) + 1);

  // Clear the buffer and await the reply
  bzero(buffer, BUFFER_SIZE);
  rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
  if (sscanf(buffer, "rpcerror %d", &error_code) == 1) {
    fprintf(stderr, "Client: Bad request: ");
    switch(error_code) {
    case ERR_INVALID_OP:
      fprintf(stderr, "Invalid message format\n");
      break;
    case ERR_TOO_FEW_ARGS:
      fprintf(stderr, "No filename specified\n");
      break;
    case ERR_TOO_MANY_ARGS:
      fprintf(stderr, "Too many file names provided\n");
      break;
    }
  } else if (sscanf(buffer, "fileerror %d", &error_code) == 1) {
    fprintf(stderr, "Client: Could not retrieve file: %s\n", strerror(error_code));
  }else if (sscanf(buffer, "%d", &error_code) == SENTINAL) { //If sentinal value is sent from server, means directory error occurred, 
    fprintf(stderr, "Client: Could not open directory %s\n", strerror(error_code));
  }else {
    writefd = creat(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    do {
      total += rcount;
      write(writefd, buffer, rcount);
      rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
    } while (rcount > 0);
    close(writefd);
    fprintf(stdout, "Client: Successfully transferred file '%s' (%d bytes) from server\n", filename, total);
  }
  // *****************************Play Audio************************************
    
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "Could not open %s: %s\n", filename, strerror(errno));
      return EXIT_FAILURE;
    }
    
    lseek(fd, -128L, SEEK_END);

    // Read the 128-byte ID3 tag from the end of the file
    read(fd, bf, 128);
    close(fd);

    // First 3 bytes are "ID3". Next 30 bytes after that are the song title
    strncpy(title, bf+3, 30);
    // Next 30 bytes after title are the artist name
    strncpy(artist, bf+33, 30);
    // Next 30 bytes after artist are the album name
    strncpy(album, bf+63, 30);
    // After the album name is the year the album was released
    strncpy(year, bf+93, 4);

    printf("Now Playing:\n  Title: %s\n", title);
    printf("  Artist: %s\n", artist);
    printf("  Album: %s\n", album);
    printf("  Year: %s\n", year);

    // Initialize the SDL2 Mixer and check for error
    result = Mix_Init(flags);
    if (flags != result) {
      fprintf(stderr, "Could not initialize mixer (result: %d).\n", result);
      fprintf(stderr, "playaudio: %s\n", Mix_GetError());
      return EXIT_FAILURE;
    }

    // Open the MP3 file. 44.1kHz represents the sample rate, 2 = stereo,
    // and 1024 means the file will be processed in 1 KB chunks.
    if (Mix_OpenAudio(44100, AUDIO_S16SYS, 2, 1024) < 0) {
      fprintf(stderr, "playaudio: %s\n", Mix_GetError());
      return EXIT_FAILURE;
    }

    // Loads the music file given
    Mix_Music *music = Mix_LoadMUS(filename);
    if(!music) {
      fprintf(stderr, "playaudio: %s\n", Mix_GetError());
      return EXIT_FAILURE;
    }

    // Play the music! The second parameter sets the number of times to play
    // the song. A value of -1 is used for looping.
    Mix_PlayMusic(music, 1);

    // This needs to be here otherwise the program terminates immediately.
    // Delay value doesn't seem to matter much. Once the music stops playing,
    // program exits the loop and terminates.
    while (1) {
      SDL_Delay(200);
      if (Mix_PlayingMusic() == 0)
        break;
    }

    // Clean up dynamically allocated memory
    Mix_FreeMusic(music);
    Mix_CloseAudio();
    Mix_Quit();
  // *****************************Play Audio************************************
  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  fprintf(stdout, "Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);
    }
  }

  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  fprintf(stdout, "Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);
  
  return(0);
}
