1. open een powershell in the folder "grading"
2. copy the assignment solution TxHandler.java to the folder "grading"
2. javac -cp "scroogeCoinGrader.jar;rsa.jar;algs4.jar;." TestTxHandler.java
3. java -cp "scroogeCoinGrader.jar;rsa.jar;algs4.jar;." TestTxHandler
(in powershell, put the classpath in double quotes)

Note: If you are using IDE like eclipse, just add jar files to your build path and create a folder for all text files within the working directory of your code.



Jar Files:


1) rsa.jar: Contains classes for using RSAKeys

2) algs4.jar: Contains some useful classes like defining priority queues, stacks, etc.

3) scroogeCoinGrader.java: Contains classes used for grading the submitted files.