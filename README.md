# MP3GroupProject
Authenticates the user then opens and plays an MP3 audio file given as a command line argument.
/           Also outputs artist, title, album, and year information saved in
/           the 128-byte ID3 tag at the end of the file (ID3v1).
/           
/           To build the play part of the program, you must install both the libsdl2-dev library
/           as well as the SDL2_mixer library:
/           
/           sudo apt-get install -y libsdl2-dev libsdl2-mixer-2.0-0 libsdl2-mixer-dev
/           
/           To build the SQLite3 database part, you must install the SQLite3 library
/           
/           sudo apt install sqlite3
/           The program will build and maintain the USERS table in the database by itself however the 
/           anytime the server is closed the hashing algorithm's rand() changes and affects the hashes 
/           referenced in the database during login so it is best if the server is never closed during testing.
/
/           To run, access the main project folder and run the make file with make.
/           navigate to /serverdata and run ./server to run the server end.
/           navigate to /clientdata and run ./client localhost to run the client end.
/           the program's login commands are case sensitive to help with readability 
/           and the program comes preloaded with Drive.mp3 to use for transfer and play
