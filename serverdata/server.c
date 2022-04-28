/******************************************************************************

PROGRAM:  server.c
AUTHOR:   Tristan Chavez, Nhi La, Wega Kinoti
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: The server end for sending and authenticating for Mp3 files. Clears SQL database after closing

******************************************************************************/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <crypt.h>
#include <termios.h>
#include <stdlib.h>
#include <time.h>
#include <sqlite3.h>

#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

#define BUFFER_SIZE       256
#define PATHLENGTH        256
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define SEED_LENGTH       8
#define PASSWORD_LENGTH   32

#define ERR_TOO_FEW_ARGS  1
#define ERR_TOO_MANY_ARGS 2
#define ERR_INVALID_OP    3

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of the 
machine to that socket, then listens on the socket for incoming TCP connections.

*******************************************************************************/
int create_socket(unsigned int port)
{
    int    s;
    struct sockaddr_in addr;

    // First we set up a network socket. An IP socket address is a combination
    // of an IP interface address plus a 16-bit port number. The struct field
    // sin_family is *always* set to AF_INET. Anything else returns an error.
    // The TCP port is stored in sin_port, but needs to be converted to the
    // format on the host machine to network byte order, which is why htons()
    // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
    // any available network interface on the machine, so clients can connect
    // through any, e.g., external network interface, localhost, etc.

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create a socket (endpoint) for network communication.  The socket()
    // call returns a socket descriptor, which works exactly like a file
    // descriptor for file system operations we worked with in CS431
    //
    // Sockets are by default blocking, so the server will block while reading
    // from or writing to a socket. For most applications this is acceptable.
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      {
	fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // When you create a socket, it exists within a namespace, but does not have
    // a network address associated with it.  The bind system call creates the
    // association between the socket and the network interface.
    //
    // An error could result from an invalid socket descriptor, an address already
    // in use, or an invalid network address
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
      {
	fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // Listen for incoming TCP connections using the newly created and configured
    // socket. The second argument (1) indicates the number of pending connections
    // allowed, which in this case is one.  That means if the server is connected
    // to one client, a second client attempting to connect may receive an error,
    // e.g., connection refused.
    //
    // Failure could result from an invalid socket descriptor or from using a socket
    // descriptor that is already in use.
    if (listen(s, 1) < 0)
      {
	fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    fprintf(stdout, "Server: Listening on TCP port %u\n", port);

    return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in 
this program.  The function SSL_load_error_strings registers the error strings 
for all of the libssl and libcrypto functions so that appropriate textual error 
messages can be displayed when error conditions arise.  OpenSSL_add_ssl_algorithms 
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl()
{
    EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters 
for the connection, and in this program, each context is configured using the 
configure_context() function below. Each context object is created using the 
function SSL_CTX_new(), and the result of that call is what is returned by this 
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context()
{
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid getting
                                // a warning from the call to SSLv23_server_method()
        SSL_CTX*    ssl_ctx;

    // Use SSL/TLS method for server
    ssl_method = SSLv23_server_method();

    // Create new context instance
    ssl_ctx = SSL_CTX_new(ssl_method);
    if (ssl_ctx == NULL)
      {
	fprintf(stderr, "Server: cannot create SSL context:\n");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }

    return ssl_ctx;
}

/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL 
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto(). 
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx)
{
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    // Set the certificate to use, i.e., 'cert.pem' 
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0)
      {
	fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }

    // Set the private key contained in the key file, i.e., 'key.pem'
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 )
      {
	fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
}

static int callback(void* data, int argc, char** argv, char** azColName)
{
    int i;
  
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
  
    printf("\n");
    return 0;
}

static int lookup(void* data, int argc, char** argv, char** azColName)
{
    int *i = (int*)data;
  
    *i = 1;
    //printf("FOUND\n"); debug
    return 0;
}

int main(int argc, char **argv)
{
    SSL_CTX*     ssl_ctx;
    unsigned int sockfd;
    unsigned int port;

    char         filename[PATHLENGTH];
    char         extra[PATHLENGTH];
    
    struct dirent* currentEntry;
    struct stat    fileInfo;
    char           olddir[PATHLENGTH];
    char           dirname[PATHLENGTH];
    DIR*           d;
    int            sentinal;
    sqlite3*           DB;
    char         password[PASSWORD_LENGTH];
    char	 username[BUFFER_SIZE];
    char	 verifyUsername[BUFFER_SIZE];
    char         hash[BUFFER_SIZE];
    char         verifyHash[BUFFER_SIZE];
    char         verifyPassword[PASSWORD_LENGTH];
    char         *seedchars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char         salt[] = "$5$........";

    srand(time(0));

    // Convert the salt into printable characters from the seedchars string
    for (int i = 0; i < SEED_LENGTH; i++)
      salt[3+i] = seedchars[rand() % strlen(seedchars)];

    // Initialize and create SSL data structures and algorithms
    init_openssl();
    ssl_ctx = create_new_context();
    configure_context(ssl_ctx);

    // Port can be specified on the command line. If it's not, use the default port 
    switch(argc)
      {
        case 1:
	  port = DEFAULT_PORT;
	  break;
        case 2:
  	  port = atoi(argv[1]);
	  break;
        default:
	  fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
	  exit(EXIT_FAILURE);
      }

    // This will create a network socket and return a socket descriptor, which is
    // and works just like a file descriptor, but for network communcations. Note
    // we have to specify which TCP/UDP port on which we are communicating as an
    // argument to our user-defined create_socket() function.
    sockfd = create_socket(port);

    // Wait for incoming connections and handle them as the arrive
    while(true)
      {
        SSL*               ssl;
	int                client;
	int                readfd;
	int                rcount;
        int                wcount;
        const  char        reply[] = "Hello World!";
        struct sockaddr_in addr;
        unsigned int       len = sizeof(addr);
	char               client_addr[INET_ADDRSTRLEN];
        sqlite3_stmt       *res;
        int                exitError = 0;
        int                id = 1;
        int                queryFound = 0;
        char               sqldb[] = "CREATE TABLE IF NOT EXISTS USERS(\nID INTEGER PRIMARY KEY,\n NAME TEXT NOT NULL,\n PASSWORD TEXT NOT NULL);";
	char*              messageError;
        char               select[BUFFER_SIZE];
        char               buffer[BUFFER_SIZE];
        char               insert[BUFFER_SIZE];

	// Once an incoming connection arrives, accept it.  If this is successful, we
	// now have a connection between client and server and can communicate using
	// the socket descriptor
        client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0)
	  {
            fprintf(stderr, "Server: Unable to accept connection: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
	  }

	// Display the IPv4 network address of the connected client
	inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr, INET_ADDRSTRLEN);
	fprintf(stdout, "Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);
	
	// Here we are creating a new SSL object to bind to the socket descriptor
        ssl = SSL_new(ssl_ctx);

	// Bind the SSL object to the network socket descriptor.  The socket descriptor
	// will be used by OpenSSL to communicate with a client. This function should
	// only be called once the TCP connection is established.
        SSL_set_fd(ssl, client);

	// The last step in establishing a secure connection is calling SSL_accept(),
	// which executes the SSL/TLS handshake.  Because network sockets are
	// blocking by default, this function will block as well until the handshake
	// is complete.
        if (SSL_accept(ssl) <= 0)
	  {
	    fprintf(stderr, "Server: Could not establish secure connection:\n");
            ERR_print_errors_fp(stderr);
          }
        else
	  fprintf(stdout, "Server: Established SSL/TLS connection with client (%s)\n", client_addr);
	
        char x[BUFFER_SIZE], y[BUFFER_SIZE];
        bzero(buffer, BUFFER_SIZE);

        // Opens database with error checking
        exitError = sqlite3_open("users.db", &DB);
        
        if (exitError) {
          fprintf(stderr, "Server: ERROR: opening database\nSQL: %s\n", messageError);
          return (-1);
        }
        else
          fprintf(stdout, "Server: Opened database successfully\n");

        //Creates sql table
        exitError = sqlite3_exec(DB, sqldb, NULL, 0, &messageError);
  
        if (exitError != SQLITE_OK) {
          fprintf(stderr, "Server: ERROR: creating table\nSQL: %s\n", messageError);
          sqlite3_free(messageError);
        }
        else
          fprintf(stdout, "Server: Table created successfully\n");

        // Runs code for startup procedures
        do {
          bzero(buffer, BUFFER_SIZE);
          rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
          //fprintf(stderr, "%s\n", buffer); debug

          //Sign in procedures
          if (sscanf(buffer, "SIGNIN %s %s", x, y) == 2) {
            fprintf(stdout, "Server: Signing in to Previous Account\n");
            strncpy(verifyHash, crypt(y, salt), BUFFER_SIZE);
            //fprintf(stdout, "%s\n", x); debug
            //fprintf(stdout, "%s\n", y); debug
            //fprintf(stdout, "%s\n", verifyHash); debug
            snprintf(select, BUFFER_SIZE*3, "SELECT NAME FROM USERS WHERE NAME=\"%s\" AND PASSWORD=\"%s\";", x, verifyHash);
            //fprintf(stdout, "%s\n", select); debug
            bzero(buffer, BUFFER_SIZE);

            int rc = sqlite3_exec(DB, select, lookup, &queryFound, &messageError);
  
            if (rc != SQLITE_OK) {
              fprintf(stderr, "ERROR: SELECT %s\n", messageError);
              wcount = SSL_write(ssl, "ERROR: SERVER: SQL SELECT error, please try again.", BUFFER_SIZE);
            }
            else {
              if (queryFound == 1) {
                fprintf(stdout, "Server: Signed in user: %s\n", x);
                wcount = SSL_write(ssl, x, BUFFER_SIZE);
              }
              else {
                fprintf(stdout, "Server: User: %s not found\n", x);
                wcount = SSL_write(ssl, "ERROR: SIGNINWRONG", BUFFER_SIZE);
              }
            }
            
            queryFound = 0;
            //char query[BUFFER_SIZE] = "SELECT * FROM USERS;"; debug
            //sqlite3_exec(DB, query, callback, NULL, NULL); debug
          }
          
          // Create account procedures
          else if (sscanf(buffer, "CREATE %s %s", x, y) == 2) {
            fprintf(stderr, "Server: Creating New Account\n");
            //fprintf(stdout, "%s\n", x); debug
            strncpy(hash, crypt(y, salt), BUFFER_SIZE);
            //fprintf(stdout, "%s\n", y); debug
            //fprintf(stdout, "%s\n", hash); debug
            bzero(buffer, BUFFER_SIZE);

            
            // Checks if username or password has already been used
            snprintf(select, BUFFER_SIZE*3, "SELECT NAME FROM USERS WHERE NAME=\"%s\" OR PASSWORD=\"%s\";", x, hash);
            //fprintf(stdout, "%s\n", select); debug
            int rc = sqlite3_exec(DB, select, lookup, &queryFound, &messageError);
  
            if (rc != SQLITE_OK) {
              fprintf(stderr, "Server: ERROR: SELECT %s\n", messageError);
              wcount = SSL_write(ssl, "ERROR: SERVER: SQL SELECT error, please try again.", BUFFER_SIZE);
            }
            else {
              //fprintf(stdout, "Operation OK!\n"); debug
              // If the name or password has not been used yet
              if (queryFound == 0) {
                //Code to insert new values
                snprintf(insert, BUFFER_SIZE*3, "INSERT INTO USERS(NAME, PASSWORD) VALUES(\"%s\", \"%s\");", x, hash);
               //fprintf(stdout, "%s\n", insert); debug

                exitError = sqlite3_exec(DB, insert, NULL, 0, &messageError);
                if (exitError != SQLITE_OK) {
                  fprintf(stderr, "Server: ERROR: inserting to table\nSQL: %s\n", messageError);
                  sqlite3_free(messageError);
                  wcount = SSL_write(ssl, "ERROR: SERVER: SQL SELECT error, please try again.", BUFFER_SIZE);
                }
                else {
                  fprintf(stdout, "Server: Records created successfully\n");
                  wcount = SSL_write(ssl, x, BUFFER_SIZE);
                }
              }
              else {
                fprintf(stdout, "Server: Username or password already taken\n");
                wcount = SSL_write(ssl, "ERROR: TAKEN", BUFFER_SIZE);
              }
            }
            queryFound = 0;
            //char query[BUFFER_SIZE] = "SELECT * FROM USERS;"; debug
            //sqlite3_exec(DB, query, callback, NULL, NULL); debug
          }
        } while (strncmp(buffer, "CANCEL", 9) != 0 && strncmp(buffer, "LOGGED IN", 9) != 0);

        if(strncmp(buffer, "LOGGED IN", 9) == 0) {
          //************************Directory Listing Stuff****************************
          if (argc == 1) {
            strncpy(dirname, ".", 2);
          } else {
            strncpy(dirname, argv[1], PATHLENGTH);
            chdir(dirname);
          }

          // Save the current working directory so that stat will work properly
          // when getting the size in bytes of files in a different directory
          getcwd(olddir, PATHLENGTH);

          // Open the directory and check for error, if error send sentinal value to client showing error
          d = opendir(dirname);
          if (d == NULL) {
            fprintf(stderr, "Could not open directory %s: %s\n", dirname, strerror(errno));
              sentinal = -1;
            return sentinal;
          }

          // Change to the directory being listed so that the calls to stat on each
          // directory entry will work correctly
          chdir(dirname);
          
          // Read each entry in the directory and display name and size
          currentEntry = readdir(d);
          
          // Iterate through all directory entries
         
          while(currentEntry != NULL) {
            
            // Use stat to get the size of the file in bytes.  If the program is listing
            // a directory other than the working directory of this program, the stat
            // call here will not work properly since d_name is relative
            if (stat(currentEntry->d_name, &fileInfo) < 0)
              fprintf(stderr, "stat: %s: %s\n", currentEntry->d_name, strerror(errno));

            // Check to see if the item is a subdirectory
            if (S_ISDIR(fileInfo.st_mode)) {
              fprintf(stdout, "%-30s\t<dir>\n", currentEntry->d_name);
            } else {
              fprintf(stdout, "%-30s\t%lu bytes\n", currentEntry->d_name, fileInfo.st_size);
            }

            // Get the next directory entry
            currentEntry = readdir(d);
          }

          // Change back to the original directory from where the program was invoked
          chdir(olddir);
          
          closedir(d);

          // **********************Sending File**************************************
	  // Receive RPC request and transfer the file
          bzero(buffer, BUFFER_SIZE);
          rcount = SSL_read(ssl, buffer, BUFFER_SIZE);

          // Check for invalid operation by comparing the first 9 chars to "download "
          if (strncmp(buffer, "download ", 9) != 0) {
            sprintf(buffer, "rpcerror %d", ERR_INVALID_OP);
            SSL_write(ssl, buffer, strlen(buffer) + 1);
          }

          // Check for too many parameters
          else if (sscanf(buffer, "download %s %s", filename, extra) == 2) {
            sprintf(buffer, "rpcerror %d", ERR_TOO_MANY_ARGS);
            SSL_write(ssl, buffer, strlen(buffer) + 1);
          }

          // Check for too few parameters
          else if (sscanf(buffer, "download %s", filename) != 1) {
            sprintf(buffer, "rpcerror %d", ERR_TOO_FEW_ARGS);
            SSL_write(ssl, buffer, strlen(buffer) + 1);
          }
  
          // Check for the correct number of parameters
          else if (sscanf(buffer, "download %s", filename) == 1) {

            // Now check for a file error
            readfd = open(filename, O_RDONLY);
            if (readfd < 0) {
              fprintf(stderr, "Server: Could not open file \"%s\": %s\n", filename, strerror(errno));
              sprintf(buffer, "fileerror %d", errno);
              SSL_write(ssl, buffer, strlen(buffer) + 1);
            }

            // Passed all error checks, so transfer the file contents to the client
            else {
              do {
                rcount = read(readfd, buffer, BUFFER_SIZE);
                SSL_write(ssl, buffer, rcount);
              } while (rcount > 0);
              close(readfd);
              // ************************************************************************

              // File transfer complete
              fprintf(stdout, "Server: Completed file transfer to client (%s)\n", client_addr);
            }
          }  
        fprintf(stdout, "Server: Completed with client (%s)\n", client_addr);
        // Terminate the SSL session, close the TCP connection, and clean up
        fprintf(stdout, "Server: Terminating SSL session and TCP connection with client (%s)\n", client_addr);
        sqlite3_close(DB);
        SSL_free(ssl);
        close(client);
        }
      }
    //Tear down SQL before terminating
    sqlite3_exec(DB, "DELETE FROM USERS;", NULL, 0, NULL);
    sqlite3_exec(DB, "DROP TABLE USERS;", NULL, 0, NULL);
    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return 0;
}
