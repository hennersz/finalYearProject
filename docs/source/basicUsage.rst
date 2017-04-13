.. _basicUsage:

Basic Usage
===========

To start the server you will also need a bootstrap server to connect to.
For testing purposes you can run one locally. Do the following::

  $ cd path/to/finalYearProject/bin
  $ twistd -noy server.tac

Then modify the config file to set bootstrapserver to 127.0.0.1

Starting the server
-------------------
::

  $ ./main.py startServer &


Stopping the server
-------------------
::

  $ ./main.py stopServer


Running a command
-----------------
::

  $ ./main.py runCommand "The command"


Available commands
------------------

.. tabularcolumns:: |l|c|

+---------+-------------------------------------+
|Command  |Args                                 | 
+=========+=====================================+
|LIST     |showPrivate - Bool                   |
+---------+-------------------------------------+
|GET KEY  |keyId - Hash or name                 |
+---------+-------------------------------------+
|SET KEY  |keyId - Hash or name                 |
+---------+-------------------------------------+
|GET CERTS|keyId - Hash or name                 |
+---------+-------------------------------------+
|SET CERTS|keyId - Hash or name                 |
+---------+-------------------------------------+
|NAME     |subjectId - Hash or name             |
|         +-------------------------------------+
|         |name - name to associate with the key|   
|         +-------------------------------------+
|         |issuerId(Optional) - Hash or name    |
+---------+-------------------------------------+
|TRUST    |subjectId - Hash or name             |
|         +-------------------------------------+
|         |issuerId(Optional) - Hash or name    |
+---------+-------------------------------------+
|TRUSTCA  |subjectId - Hash or name             |
|         +-------------------------------------+
|         |Delegate - Bool, delegate permision  |   
|         +-------------------------------------+
|         |issuerId(Optional) - Hash or name    |
+---------+-------------------------------------+
|IDENTIFY |keyId - Hash or name                 |
+---------+-------------------------------------+
|STOP     |None                                 |
+---------+-------------------------------------+
