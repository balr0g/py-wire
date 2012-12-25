# Copyright (c) 2004 Quasi Reality
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
# SOFTWARE.

'''Module for interacting with a Wired Server'''

import socket
from tlslite.api import *
from tlslite import __version__ as tlsversion
import sha
import thread
import time
import os
import sys
import logging
import cPickle

__version__ = '0.1'

## Default logger

class PrintHandler(logging.Handler):
    """Handler for log message using the print statement"""
    def __init__(self):
        logging.Handler.__init__(self)
    def emit(self, record):
        """Send log message to standard output using print
        
        record (logging.LogRecord) - record
        """
        print ("%s: %s" % (record.levelname, record.msg.encode('utf8','ignore')))
        
printlogger = logging.getLogger('print')
printlogger.addHandler(PrintHandler())
printlogger.setLevel(logging.DEBUG)

## Miscellaneous functions not related to class wire

def parsewiredtime(timestring):
    """Parse the time given by a Wired into Python's native time format"""
    return time.strptime(timestring[:19],'%Y-%m-%dT%H:%M:%S')

## Data structures used by wire

class wireuser:
    """Information relating to a user on Wired server"""
    def __init__(self, id, isidle, isadmin, icon, nick, login, ip, dnsname = ''):
        """Initialize user on Wired server
        
        id (int) - id of user
        isidle (bool) - whether the user is currently idle
        isadmin (bool) - whether the user is an admin
        icon (int) - number of user's icon
        nick (str) - nickname of user
        login (str) - name of account user used to login
        ip (str) - IP address of user's connection
        dnsname (str) - reverse DNS lockup for user's IP address
        """
        self.id = int(id)
        self.chats = []
        self.downloads, self.uploads = {}, {}
        self.clientversion, self.ciphername = None, None
        self.cipherbits, self.logintime, self.idletime = None, None, None
        self.updatestatus(isidle, isadmin, icon, nick)
        self.updateinfo(login, ip, dnsname)
        
    def __unicode__(self):
        transferlist = "Downloads:\n"
        for download in self.downloads:
            transferlist += "%s\n" % unicode(download)
        transferlist += "\n\nUploads:\n"
        for upload in self.uploads:
            transferlist += "%s\n" % unicode(upload)
        logintime, idletime = None, None
        if self.logintime != None:
            logintime = time.strftime('%Y-%m-%d %H:%M:%S',self.logintime)
        if self.idletime != None:
            idletime = time.strftime('%Y-%m-%d %H:%M:%S',self.idletime)
        return 'Wired User:\nid=%s \nidle=%s \nadmin=%s \nicon=%s \nnick=%s \nlogin=%s \nip=%s \nhost=%s \nclientversion=%s \nciphername=%s \ncipherbits=%s \nlogintime=%s \nidletime=%s \n\n%s' % (self.id, self.isidle, self.isadmin, self.icon, self.nick, self.login, self.ip, self.dnsname, self.clientversion, self.ciphername, self.cipherbits, logintime, idletime, transferlist)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
    def updatestatus(self, isidle, isadmin, icon, nick):
        """"Update client status
        
        isidle (bool) - whether the user is currently idle
        isadmin (bool) - whether the user is an admin
        icon (int) - number of user's icon
        nick (str) - nickname of user
        """
        self.isidle = bool(int(isidle))
        self.isadmin = bool(int(isadmin))
        self.icon = int(icon)
        self.nick = '%s' % nick
        
    def updateinfo(self, login, ip, dnsname = ''):
        """Update regular client info
        
        login (str) - name of account user used to login
        ip (str) - IP address of user's connection
        dnsname (str) - reverse DNS lockup for user's IP address
        """
        self.login = '%s' %login
        self.ip = '%s' % ip
        self.dnsname = '%s' % dnsname
        return 0
        
    def updateextendedinfo(self, clientversion, ciphername, cipherbits, logintime, idletime, downloads = {}, uploads = {}):
        """Update extended client info
        
        clientversion (str) - client version string that user sent on connection
        ciphername (str) - name of cipher user is using
        cipherbits (str) - number of bits in ciphter user is using
        logintime (str) - time user logged in, in Wired format
        idletime (str) - time of user's last interactive action, in Wired format
        downloads (dict) - contains wiretransfers user is downloading
        uploads (dict) - contains wiretransfers user is uploading
        """
        self.clientversion = '%s' % clientversion
        self.ciphername = '%s' % ciphername
        self.cipherbits = int(cipherbits)
        self.logintime = parsewiredtime(logintime)
        self.idletime = parsewiredtime(idletime)
        self.downloads = downloads
        self.uploads = uploads
        
    def addchat(self, chatid):
        """Associate this user with chat
        
        chatid (int) - chat to which to associate with this user
        """
        chatid = int(chatid)
        if chatid not in self.chats:
            self.chats.append(chatid)
            return 0
        return 1
        
    def removechat(self, chatid):
        """Remove association between this user and chat
        
        chatid (int) - chat to which to disassociate with this user
        """
        chatid = int(chatid)
        if chatid not in self.chats:
            return 1
        else:
            self.chats.remove(chatid)
        return 0
            
class wirepath:
    """Information relating to a path on a Wired server"""
    def __init__(self, path, type, size):
        """Initialize record of path on server
        
        path (str) - path of file on server
        type (int) - type of path on server (0 = regular file, 1 = regular
            directory, 2 = upload directory, 3 = drop box)
        size (int) - if type=0: size of path in bytes, otherwise number of 
            files in path
        """
        self.path = '%s' % path
        self.createtime, self.modifytime, self.checksum = None, None, None
        self.updateinfo(type, size)
        self.revision = 0
        
    def updateinfo(self, type, size, createtime = None, modifytime = None, checksum = None):
        """Update info for file
        
        type (int) - type of path on server
        size (int) - if type=0: size of path in bytes, otherwise number of 
            files in path
        createtime (str) - time of creation of path, in Wired format
        modifytime (str) - time of last modification to path, in Wired format
        checksum (str) - hexdecimal sha-1 checksum of first 1MB of file
        """
        self.type = int(type)
        self.size = int(size)
        if createtime != None:
            self.createtime = parsewiredtime(createtime)
        if modifytime != None:
            self.modifytime = parsewiredtime(modifytime)
        if checksum != None:
            self.checksum = '%s' % checksum
        
    def __unicode__(self):
        createtime, modifytime = None, None
        if self.createtime != None:
            createtime = time.strftime('%Y-%m-%d %H:%M:%S',self.createtime)
        if self.modifytime != None:
            modifytime = time.strftime('%Y-%m-%d %H:%M:%S',self.modifytime)
        return 'Wired File:\npath=%s \ntype=%s \nsize=%s \ncreated=%s \nmodified=%s \nchecksum=%s \n' % (self.path, self.type, self.size, createtime, modifytime, self.checksum)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wireprivileges:
    """Information on privileges held by user
    
    All privileges can be accessed as attributes, even though they are stored
    in a list."""
    def __init__(self, privileges = None):
        """Initialize privileges for server
        
        privileges (list) - list of values of privileges, in the following 
            order: getuserinfo, broadcast, postnews, clearnews, download, 
            upload, uploadanywhere, createfolders, movefiles, deletefiles,
            viewdropboxes, createaccounts, editaccounts, deleteaccounts,
            elevateprivileges, kickusers, banusers, cannotbekicked, 
            downloadspeed, uploadspeed
        """
        # Privileges are stored in a list
        # They can be access by name as attributes by checking for which
        # position they are in the list through the mapping dictionary
        self.__dict__['privileges'] = []
        self.__dict__['mapping'] = {'getuserinfo':0, 'broadcast':1, 'postnews':2, 'clearnews':3,
            'download':4, 'upload':5, 'uploadanywhere':6, 'createfolders':7,
            'movefiles': 8, 'deletefiles':9, 'viewdropboxes':10, 
            'createaccounts':11, 'editaccounts':12, 'deleteaccounts':13,
            'elevateprivileges':14, 'kickusers':15, 'banusers':16,
            'cannotbekicked':17, 'downloadspeed':18, 'uploadspeed':19}
        if privileges != None:
            self.update(privileges)
        else:
            self.update([0]*20)
            
    def __unicode__(self):
        return "\x1c".join(map(str,(map(int,self.privileges))))
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
    
    def __len__(self):
        return 1
        
    def __getattr__(self, name):
        if name not in ('privileges','mapping'):
            return self.__dict__['privileges'][self.__dict__['mapping'][name]]
        else:
            return self.__dict__[name]
            
    def __setattr__(self, name, value):
        if name not in ('privileges','mapping'):
            self.__getattr__('privileges')[self.__getattr__('mapping')[name]] = value
        else:
            self.__dict__[name] = value
        
    def update(self, privileges):
        """Update privileges
        
        privileges (list) - list of privileges
        """
        privileges = map(int,privileges)
        self.privileges = map(bool,privileges[:18])
        self.privileges.append(privileges[18])
        self.privileges.append(privileges[19])
        return 0

class wirenewspost:
    """Information on a news article posted on a wired server"""
    def __init__(self, poster, posttime, post):
        """Initialize news post on server
        
        poster (str) - nickname user used when posting the news
        posttime (str) - time news was posted, in Wired format
        post (str) - contents of news post
        """
        self.poster = '%s' % poster
        self.posttime = parsewiredtime(posttime[:19])
        self.post = '%s' % post
        self.id = sha.new(('%s%s%s' % (poster, posttime, post)).encode('ascii','ignore')).hexdigest()
        
    def __unicode__(self):
        return "Wired News Article: \nposter=%s \nposttime=%s \n%s" % (self.poster, time.strftime('%Y-%m-%dT%H:%M:%S',self.posttime), self.post)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wireaccount:
    """Information on accounts on the Wired server"""
    def __init__(self, name, privileges, password = None, groupname = None):
        """Initialize user or group account on server
        
        name (str) - name of account (can be user or group account)
        privileges (wireprivileges) - privileges for account
        password (str) - password for account (None of group account)
        groupname (str) - name of group in which the user is (None for group 
            account)
        """
        self.name = '%s' % name
        # If you plan to change the password, you must hash it with SHA-1
        # before sending the edit account request to the server
        self.password = '%s' % password
        self.groupname = '%s' % groupname
        self.privileges = privileges
        self.isgroup = False
        self.groupname = None
        if password == None:
            self.isgroup = True
        if groupname != None:
            self.groupname = '%s' % groupname
        
    def __unicode__(self):
        if self.isgroup:
            return "%s\x1c%s" % (self.name, self.privileges)
        return "%s\x1c%s\x1c%s\x1c%s" % (self.name, self.password, self.groupname, self.privileges)

    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wiretransfer:
    """Information on uploads/downloads by clients on the Wired server"""
    def __init__(self, path, transferred, size, speed):
        """Initialize record of transfer between server and another user
        
        path (str) - path of file on server
        transferred (int) - the current position of the file being transfered
        size (int) - the total size of the file
        speed (int) - the speed of the transfer, in bytes per second
        """
        self.path = '%s' % path
        self.transferred = int(transferred)
        self.size = int(size)
        self.speed = int(speed)
        
    def __unicode__(self):
        return "Path: %s Transferred: %s Size: %s Speed: %s" % (self.path, self.transferred, self.size, self.speed)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wireupload:
    """Information on an upload by this connection to the Wired server"""
    def __init__(self, hostpath, serverpath):
        """Initialize potential upload
        
        hostpath (str) - local path to upload
        serverpath (str) - remote path at which to store uploaded files
        """
        self.hostpath = hostpath
        self.serverpath = serverpath
        if os.path.isfile(hostpath):
            self.size = os.path.getsize(hostpath)
            self.file = file(hostpath,'rb')
            self.checksum = sha.new(self.file.read(1048576)).hexdigest()
            self.file.close()
        # The start time and current file position for the upload
        self.starttime, self.fileposition = None, None
        # Should we stop downloading this file
        self.stop = False
        # Last three times an error occured while uploading the file
        self.errortimes = [0,0,0]
        
    def __unicode__(self):
        return "Upload: %s -> %s" % (self.hostpath, self.serverpath)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
            
class wiredownload:
    """Information on an download by this connection from the Wired server"""
    def __init__(self, serverpath, hostpath):
        """Initialize potential download
        
        serverpath (str) - remote path to download
        hostpath (str) - local path at which to store downloaded files
        """
        self.hostpath = hostpath
        if isinstance(serverpath, wirepath):
            self.serverfile = serverpath
            self.serverpath = serverpath.path
        else:
            self.serverpath = serverpath
            self.serverfile = None
        self.offset = 0
        self.starttime, self.fileposition = None, None
        self.stop = False
        self.errortimes = [0, 0, 0]
        
    def __unicode__(self):
        return "Download: %s -> %s" % (self.serverpath, self.hostpath)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
##  The wire class itself
    
class wire:
    """Controls connection to a server implementing the Wired protocol
    
    See http://www.zankasoftware.com/wired/rfc1.txt for description of 
    the Wired protocol.
    """
    def __init__(self,host='127.0.0.1',port=2000,nick='Default User', 
       login='guest',password='',icon=0, appname = '', 
       timeout = 15, logger = printlogger, callbacks = {}):
        """Initialize connection parameters
        
        host (str) = IP Address or DNS name of Wired server
        port (int) = port on which Wired server listens 
        nick (str) = name shown in user list
        login (str) = account name used to login
        password (str) = password for account
        icon (int) = number of icon that shows up in user list
        appname (str) = name of the application using this library
        timeout (int) = timeout for some initial connections
        logger (logging.Logger) = the python logger for the connection
        callbacks (dict) = contains callback functions, corresponding to codes
            returned from the wired server.  Keys should be 3 digit integers, 
            values should be functions. For example, if you have a key of 400 
            in callbacks, the corresponding function will be called whenever 
            the wired server returns that code.  These functions are passed 2
            arguments: the wire object and a list of the arguments to the
            server response (the response string split by the ascii field
            separator).
            
            There are also some string keys that are recognized for various 
            events that don't correspond with codes the server returns.  The 
            first argument is always this instance of wire. :            
            controlconnectionclosed(wire):
                Called whenever the control connection to the server is closed.
                Useful for reconnecting.
            downloadfinished(wire, wiredownload, success):
                Called when a download has been finished. wiredownload is the 
                download that just finished, and success is whether the 
                transfer was successful or not (i.e. no socket errors occured).
            gotunrecognizedmessage(wire, servermessage):
                Called when the server sends a message that this module
                doesn't recognize. message is the message the server sent.
            ping(wire):
                Called after pinging the server (every 10 minutes).  Useful for
                doing something on a regular basis.
            uploadfinished - Arguments: (wire, wireupload, success):
                Same as downloadfinished, but for uploads.
                
        Note: Unicode can be used for most string arguments
        """
        self.version = __version__
        self.buffersize = 8192
        self.timeout = timeout
        self.host = host
        self.port = int(port)
        self.nick = nick
        self.login = login
        self.password = password
        self.appname = appname
        self.icon = int(icon)
        self.callbacks = callbacks
        self.log = logger
        self.buffer = ''
        self.defaulthostdir = os.getcwd()
        # defaultserverdir should always end with a slash
        self.defaultserverdir = '/'
        # This library uses threads, and this lock is very important
        # Always acquire the lock before making any changes to the internal
        # data structures
        self.lock = thread.allocate_lock()
        self.maxsimultaneousdownloads, self.maxsimultaneousuploads = 1, 1
        self._resetfilestructures()
        
    ### Functions that should not be called by the user
    
    def __str__(self):
        return "Wired client, connected to %s:%s as %s" % (self.host, self.port, self.login)
        
    def __repr__(self):
        return self.__str__()
    
    def _get(self):
        """Download next file in download queue"""
        # This function should only be called while in posession of the lock
        while True:
            if self.downloadqueue == []:
                self.log.debug('_get called with nothing in downloadqueue')
                return 1
            numcurrentdownloads = len(self.currentdownloads)
            if  numcurrentdownloads >= self.maxsimultaneousdownloads:
                self.log.debug('_get called, but currently downloading %s files' % numcurrentdownloads)
                return 1
            # If you are trying to download a directory with many subdirectories
            # and files, and all of the information is already in the file and 
            # filelist caches, _get can take a very long time.  Since this 
            # library is threaded, it's not a good idea to spend a large amount
            # of time without yielding the lock. Releasing and reacquiring the
            # lock should keep programs who use this library responsive
            self.releaselock(True)
            self.acquirelock(True)
            # The download queue works partly like a stack and partly like a queue
            # It's like a queue because paths the user puts in it are downloaded
            # in a first in first out basis.  It's like a stack because it does 
            # a depth first traversal of the subdirectories and files of that
            # path, which are processed on a last in first out basis
            download = self.downloadqueue[-1]
            serverpath, hostpath = download.serverpath, download.hostpath
            self.log.debug('_get called with %s items in queue, next item download "%s" to "%s"' % (len(self.downloadqueue),serverpath,hostpath))
            if serverpath not in self.files:
                # This path should only be taken for the path actually submitted
                # by the user.  Files and subdirectories below that path should
                # already have this information by the time they get to this step
                self.getfileinfo(serverpath, False)
                return 1
            if download.serverfile == None:
                # Set the serverfile for the download, so we can access the 
                # size and checksum information, if available
                download.serverfile = self.files[serverpath]
            if self.files[serverpath].type != 0:
                # Path taken for directories
                if serverpath not in self.filelists:
                    self.getfilelist(serverpath, False)
                    return 1
                else:
                    if not os.path.exists(hostpath):
                        # If the directory we are downloading doesn't exist
                        # on the local filesystem, create it
                        os.mkdir(hostpath)
                    elif not os.path.isdir(hostpath):
                        self.log.error('Can\'t download directory "%s", destination (%s) is file ' % (serverpath, hostpath))
                        self.downloadqueue.pop()
                        continue
                # Remove the directory from the queue
                self.downloadqueue.pop()
                fils = [f for f in self.files.keys() if os.path.dirname(f) == serverpath]
                fils.sort()
                fils.reverse()
                for fil in fils:
                    # Append all subdirectories and files to the queue, 
                    # in reverse order so that the last entry will be the first
                    # alphabetically
                    self.downloadqueue.append(wiredownload(self.files[fil], os.path.join(hostpath, os.path.basename(fil))))
                continue
            else:
                # Path taken for files
                if os.path.exists(hostpath):
                    if not os.path.isfile(hostpath):
                        self.log.error('Can\'t download file "%s", destination (%s) is directory ' % (serverpath, hostpath))
                        self.downloadqueue.pop()
                        continue
                    elif self.files[serverpath].size <= os.path.getsize(hostpath):
                        self.log.debug('Download already complete: %s' % serverpath)
                        self.downloadqueue.pop()
                        continue
                    elif self.files[serverpath].checksum == None:
                        # If the file exists locally and we don't have the
                        # remote checksum, we need to get it to see if it matches
                        self.getfileinfo(serverpath, False)
                        return 1
                    fil = file(hostpath,'rb')
                    checksum = sha.new(fil.read(1048576)).hexdigest()
                    fil.close()
                    if self.files[serverpath].checksum == checksum:
                        # If the checksums match, we don't have to download the 
                        # entire file again
                        download.offset = os.path.getsize(hostpath)
                    else:
                        # If the checksums don't match, we'll try to rename the
                        # old file, or remove it if it looks like we already have
                        # a second copy of it
                        try:
                            newname = '%s__%s' % (hostpath, checksum)
                            os.rename(hostpath, newname)
                        except OSError:
                            try:
                                if os.path.exists(newname) and os.path.isfile(newname) and os.path.getsize(hostpath) == os.path.getsize(newname):
                                    os.remove(hostpath)
                            except OSError:
                                self.log.error("Skipping download of \"%s\", checksums don't match and local file (%s) couldn't be renamed or removed:" % (serverpath, hostpath))
                                self.downloadqueue.pop()
                                continue
                self.log.debug('Sending get message for transfer of "%s" to "%s"' % (serverpath, hostpath))
                self.requested['downloads'].append(serverpath)
                self.currentdownloads[serverpath] = self.downloadqueue.pop()
                self._send("GET %s\x1c%s\04" % (serverpath, download.offset))
                continue
            return 1
                      
    def _listen(self):
        """Listen for responses from server"""
        self.acquirelock(True)
        self.socket.settimeout(None)
        data = u''
        responses = {202:self.gotpong, 300:self.gotchat, 301:self.gotactionchat,
            302:self.gotclientjoin, 303:self.gotclientleave, 
            304:self.gotstatuschange, 305:self.gotprivatemessage, 
            306:self.gotclientkicked, 307:self.gotclientbanned, 
            308:self.gotuserinfo, 309:self.gotbroadcast,
            310:self.gotuserlist, 311:self.gotuserlistdone,
            320:self.gotnews, 321:self.gotnewsdone, 322:self.gotnewsposted,
            330:self.gotprivatechatcreated, 331:self.gotprivatechatinvite,
            332:self.gotprivatechatdeclined, 400:self.gottransferready,
            401:self.gottransferqueued, 402:self.gotfileinfo,
            410:self.gotfilelist, 411:self.gotfilelistdone,
            420:self.gotsearchlist, 421:self.gotsearchlistdone,
            500:self.gotcommandfailed, 501:self.gotcommandnotrecognized,
            502:self.gotcommandnotimplemented, 503:self.gotsyntaxerror,
            512:self.gotclientnotfound, 513:self.gotaccountnotfound, 
            514:self.gotaccountexists, 515:self.gotcannotbedisconnected,
            516:self.gotpermissiondenied, 520:self.gotfilenotfound,
            521:self.gotfileexists, 522:self.gotchecksummismatch,
            600:self.gotaccountspec, 601:self.gotgroupspec, 602:self.gotprivileges, 
            610:self.gotaccountlist, 611:self.gotaccountlistdone,
            620:self.gotgrouplist, 621:self.gotgrouplistdone}
        self.log.debug('Starting Listening Loop')
        self.releaselock(True)
        try:
            while not self.tlssocket.closed:
                # Get the data from the socket, and convert it to unicode
                data += self.tlssocket.recv(self.buffersize).decode('utf8')
                self.acquirelock(True)
                nextcommandend = data.find('\04')
                if nextcommandend == -1:
                    self.releaselock(True)
                    continue
                nextcommand = data[:nextcommandend]
                commandnum = int(nextcommand[:3])
                # Split the commands arguments by the ascii field separator
                args = nextcommand[4:].split("\x1C")
                data = data[nextcommandend+1:]
                self.log.debug('Server response: %s' % nextcommand)
                if commandnum in responses:
                    responses[commandnum](args)
                else:
                    self.gotunrecognizedmessage(nextcommand)
                    if 'gotunrecognizedmessage' in self.callbacks:
                        self.callbacks['gotunrecognizedmessage'](self, nextcommand)
                if commandnum in self.callbacks:
                    self.callbacks[commandnum](self, args)
                self.releaselock(True)
        except (socket.error, TLSError, ValueError):
            self.log.error("Control connection closed: %s %s %s" % sys.exc_info())
        except:
            self.log.error("Serious error in listen thread: %s %s %s" % sys.exc_info())
            self.tlssocket.close()
            self.socket.close()
            self.releaselock(True)
        self.log.info('Disconnected from server')
        if 'controlconnectionclosed' in self.callbacks:
            self.callbacks['controlconnectionclosed'](self)
            
    def _pingserver(self):
        """Ping the server on a regular basis"""
        # The only purpose of this is to keep the connection alive
        time.sleep(600)
        try:
            while not self.tlssocket.closed:
                self.acquirelock(True)
                if not self.tlssocket.closed:
                    self.log.debug('Pinging server')
                    self.requested['pong'] = True
                    self._send("PING\04")
                if 'ping' in self.callbacks:
                    self.callbacks['ping'](self)
                self.releaselock(True)
                time.sleep(600)
        except :
            self.log.error("Serious error in _pingserver thread: %s %s %s" % sys.exc_info())
            self.releaselock(True)
    
    def _put(self):
        """Upload next file in upload queue"""
        # Most of the comments in _get are also applicable here
        while True:
            if self.uploadqueue == []:
                self.log.debug('_put called with nothing in uploadqueue')
                return 1
            numcurrentuploads = len(self.currentuploads)
            if  numcurrentuploads >= self.maxsimultaneousuploads:
                self.log.debug('_put called, but currently uploading %s files' % numcurrentuploads)
                return 1
            self.releaselock(True)
            self.acquirelock(True)
            upload = self.uploadqueue[-1]
            hostpath, serverpath = upload.hostpath, upload.serverpath
            serverdir = os.path.dirname(serverpath)
            self.log.debug('_put called, queue length %s, next item upload "%s" to "%s"' % (len(self.uploadqueue), hostpath, serverpath))
            if serverdir not in self.filelists:
                # Since you may be uploading a file or directory that doesn't  
                # yet exist on the server, you can't call getfileinfo.
                # However, the parent directory of the file should exist, so 
                # check that and see if the path we are uploading already exists
                if serverdir not in self.requested['filelists']:
                    self.getfilelist(serverdir, False)
                return 1
            elif serverdir not in self.files:
                # Need to check to see if serverdir is an upload directory
                if serverdir not in self.requested['fileinfo']:
                    self.getfileinfo(serverdir, False)
                return 1
            elif os.path.isdir(hostpath):
                if serverpath not in self.files:
                    if not self.privileges.createfolders :
                        self.log.warning("You don't have the privileges to create folders")
                        self.uploadqueue.pop()
                        continue
                    # Unfortunately, we can't check if the creation is succesful
                    self.createfolder(serverpath, False)
                elif self.files[serverpath].type == 0:
                    self.log.error('Can\'t upload directory "%s", destination (%s) is file ' % (hostpath, serverpath))
                    self.uploadqueue.pop()
                    continue
                fils = os.listdir(hostpath)
                fils.sort()
                fils.reverse()
                self.uploadqueue.pop()
                for fil in fils:
                    self.uploadqueue.append(wireupload(os.path.join(hostpath,fil), "%s/%s" % (serverpath, fil)))
            elif os.path.isfile(hostpath):
                if self.files[serverdir].type == 1 and not self.privileges.uploadanywhere:
                    self.log.error("You don't have the privileges to upload anywhere, try uploading to an Uploads folder.")
                    self.uploadqueue.pop()
                    continue
                if serverpath in self.files:
                    if self.files[serverpath].type != 0:
                        self.log.error('Can\'t upload file "%s", destination (%s) is directory ' % (hostpath, serverpath))
                        self.uploadqueue.pop()
                        continue
                    elif self.files[serverpath].size >= upload.size:
                        self.log.debug('Upload already complete: %s' % hostpath)
                        self.uploadqueue.pop()
                        continue
                    elif self.filelists[serverdir]['freeoctets'] < upload.size - self.files[serverpath].size:
                        self.log.debug('Not enough space to upload: %s' % hostpath)
                        self.uploadqueue.pop()
                        continue
                elif self.filelists[serverdir]['freeoctets'] < upload.size:
                    self.log.debug('Not enough space to upload: %s' % hostpath)
                    self.uploadqueue.pop()
                    continue
                self.log.debug('Sending put message for transfer of "%s" to "%s"' % (hostpath, serverpath))
                self.requested['uploads'].append(serverpath)
                self.currentuploads[serverpath] = self.uploadqueue.pop()
                self._send("PUT %s\x1c%s\x1c%s\04" % (serverpath, upload.size, upload.checksum))
                continue
            else:
                # Must be something special if it's not a file or directory
                # Or maybe it doesn't exist
                # In case case, better off not uploading it
                self.uploadqueue.pop()
        
    def _receivefile(self, transfer, offset, hash):
        """Connect to transfer port and download file
        
        transfer (wiredownload) - the wiredownload to receive
        offset (int) - the offset at which to begin the file writing (should be
            at the end of the file)
        hash (str) - the hash corresponding to this transfer request
        """
        hostpath = transfer.hostpath
        serverpath = transfer.serverpath
        filsize = transfer.serverfile.size
        buffersize = self.buffersize
        self.log.debug('Opening file for download %s' % hostpath)
        fil = file(hostpath,'a+b')
        fil.seek(int(offset))
        self.log.debug('Connecting to transfer socket')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host,self.port+1))
            tlssocket = TLSConnection(sock)
            tlssocket.handshakeClientCert()
            self.log.debug('Sending transfer request for download %s' % serverpath)
            # Don't need to utf encode this because hash is always hexadecimal
            tlssocket.send("TRANSFER %s\04" % hash)
            sock.settimeout(None)
            success = True
            self.log.info('Starting download of %s at offset %s' % (serverpath, offset))
            transfer.starttime = time.time()
            while not tlssocket.closed and fil.tell() < filsize and not transfer.stop:
                data = tlssocket.recv(self.buffersize)
                fil.write(data)
                transfer.fileposition = fil.tell()
            self.log.info('Finished downloading %s' % serverpath)
        except (socket.error, TLSError, ValueError):
            self.log.error("Download connection closed: %s %s %s" % sys.exc_info())
            success = False
        except:
            self.log.error("Serious error in _sendfile thread: %s %s %s" % sys.exc_info())
            success = False
        if not tlssocket.closed:
            tlssocket.close()
        sock.close()
        fil.close()
        self.acquirelock(True)
        if 'downloadfinished' in self.callbacks:
            self.callbacks['downloadfinished'](self, transfer, success)
        if success and serverpath in self.currentdownloads:
            del self.currentdownloads[serverpath]
        else:
            curtime = time.time()
            errortime = curtime - transfer.errortimes.pop(0)
            transfer.errortimes.append(curtime)
            if errortime < 120 and self.downloadqueue != [] and \
               self.downloadqueue[-1].hostpath == hostpath:
                self.log.info("Many recurrent errors downloading in a short period, skipping download of %s" % hostpath)
            else:
                self.downloadqueue.append(self.currentdownloads[serverpath])
                del self.currentdownloads[serverpath]
        if not self.tlssocket.closed:
            # If the control connection is still open, might as well try to get
            # the next file (or this one again if it didn't finish properly)
            try:
                self._get()
            except (ValueError, socket.error, TLSError):
                pass
        self.releaselock(True)
        return 0
        
    def _resetfilestructures(self):
        """Reset various internal file structures"""
        self.chats, self.users, self.files, self.filelists = {}, {}, {}, {}
        self.accounts, self.groups, self.privatechatinvites = {}, {}, {}
        self.searches, self.currentdownloads, self.currentuploads = {}, {}, {}
        self.news, self.uploadqueue, self.downloadqueue = [], [], []
        self.privileges = wireprivileges()
        self.requested = {'accountlist':False, 'grouplist':False, 'pong':False,
            'readuser':[], 'readgroup':[], 'news':False, 'filelists':[],
            'searchlists':[], 'fileinfo':[], 'privatechat':0, 'userinfo':[],
            'userlist':[], 'privileges':False, 'uploads':[], 'downloads':[]}
        
    def _send(self, data):
        """Send a command to the Wired server
        
        data (str) - data to send to the Wired server
        """
        self.log.debug('Sending command to server: %s' % data)
        data = data.encode('utf-8')
        try:
            self.tlssocket.send(data)
        except (socket.error, TLSError, AttributeError, ValueError):
            self.log.error("Error sending message to server")
            return 1
        return 0
            
    def _sendfile(self, transfer, offset, hash):
        """Connect to transfer port and upload file
        
        transfer (wireupload) - the wireupload to transfer
        offset (int) - the offset at which to start the transfer
        hash (str) - the hash corresponding to this transfer request
        """
        # See comments in receive file, as these operate similarly
        hostpath, serverpath = transfer.hostpath, transfer.serverpath
        buffersize = self.buffersize
        filsize = os.path.getsize(hostpath)
        self.log.debug('Opening file for upload %s' % hostpath)
        fil = file(hostpath,'rb')
        fil.seek(int(offset))
        self.log.debug('Connecting to transfer socket')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host,self.port+1))
            tlssocket = TLSConnection(sock)
            tlssocket.handshakeClientCert()
            self.log.debug('Sending transfer request for upload %s' % hostpath)
            tlssocket.send("TRANSFER %s\04" % hash)
            sock.settimeout(None)
            success = True
            self.log.info('Starting upload of %s at offset %s' % (hostpath, offset))
            transfer.starttime = time.time()
            while not tlssocket.closed and fil.tell() < filsize and not transfer.stop:
                tlssocket.send(fil.read(self.buffersize))
                transfer.fileposition = fil.tell()
            if serverpath not in self.files:
                self.files[serverpath] = wirepath(serverpath, 0, filsize)
            else:
                self.getfileinfo(serverpath)
            self.log.info('Finished uploading %s' % hostpath)
        except (socket.error, TLSError, ValueError):
            self.log.error("Upload connection closed: %s %s %s" % sys.exc_info())
            self.getfileinfo(serverpath)
            success = False
        except:
            self.log.error("Serious error in _sendfile thread: %s %s %s" % sys.exc_info())
            self.getfileinfo(serverpath)
            success = False
        if not tlssocket.closed:
            tlssocket.close()
        sock.close()
        fil.close()
        self.acquirelock(True)
        if 'uploadfinished' in self.callbacks:
            self.callbacks['uploadfinished'](self, transfer, success)
        if success and serverpath in self.currentuploads:
            del self.currentuploads[serverpath]
        else:
            curtime = time.time()
            errortime = curtime - transfer.errortimes.pop(0)
            transfer.errortimes.append(curtime)
            if errortime < 120 and self.uploadqueue != [] and \
               self.uploadqueue[-1].hostpath == hostpath:
                self.log.info("Many recurrent errors uploading in a short period, skipping upload of %s" % transfer.hostpath)
            else:
                self.uploadqueue.insert(0,self.currentuploads[serverpath])
                del self.currentuploads[serverpath]
        if not self.tlssocket.closed:
            try:
                self._put()
            except (ValueError, socket.error, TLSError):
                pass
        self.releaselock(True)
        return 0
        
    ### Utility Functions
    
    def acquirelock(self, lock = True):
        """Acquire the lock if argument is True"""
        # Python thread doesn't support conditionally acquiring the lock based
        # on a boolean argument.  More exactly, the acquire method can acquire
        # the lock even if the boolean is false, which isn't what we want
        if lock:
            self.lock.acquire()
        return 0
    
    def clearuploadqueue(self, lock = True):
        """Clear the upload queue"""
        self.acquirelock(lock)
        self.log.debug('Clearing the upload queue')
        self.uploadqueue = []
        self.releaselock(lock)
        return 0
        
    def cleardownloadqueue(self, lock = True):
        """Clear the download queue"""
        self.acquirelock(lock)
        self.log.debug('Clearing the download queue')
        self.downloadqueue = []
        self.releaselock(lock)
        return 0
        
    def forgetpath(self, path, lock = True):
        """Forget path and all subpaths
        
        path (str) - path to forget"""
        # If any of the paths in the upload or download queue are subpaths of
        # this path, you may run into problems later
        self.acquirelock(lock)
        self.log.debug('Forgetting all paths starting with %s' % path)
        for fil in [f for f in self.files if f.startswith(path)]:
            del self.files[fil]
        for fil in [f for f in self.filelists if f.startswith(path)]:
            del self.filelists[fil]
        self.releaselock(lock)
        return 0
        
    def normpaths(self, hostpath, serverpath):
        """Normalize relative paths for uploads and downloads
        
        hostpath (str) - if relative path, make absolute path using default host
            directory
        serverpath (str) - if relative path, make absolute path using default server
            directory"""
        if os.path.dirname(hostpath) == '':
            hostpath = os.path.join(self.defaulthostdir, hostpath)
        if serverpath and serverpath[0] != '/':
            serverpath = self.defaultserverdir + serverpath
        return (hostpath, serverpath)
        
    def releaselock(self, lock = True):
        """Release the lock if argument is True"""
        if lock:
            self.lock.release()
        return 0
        
    def restartdownloadqueueifpathmatches(self, path, requested = False):
        """Check the download queues and restart download if necessary
        
        path (str) - path to check.  If it matches the next path in the download
            queue, drop the next entry and reprocess the queue
        requested (bool) - whether a get request has been sent for this download
        """
        if not requested and self.downloadqueue != [] and self.downloadqueue[-1].starttime == None and \
           path == self.downloadqueue[-1].serverpath:
            self.log.warning('Problem with path, skipping download of %s' % path)
            self.downloadqueue.pop()
            self._get()
            return 0 
        elif requested and path in self.currentdownloads:
            self.log.warning('Problem with path, skipping download of %s' % path)
            del self.currentdownloads[path]
            self._get()
            return 0
        return 1
        
    def restartuploadqueueifpathmatches(self, path, requested = False):
        """Check the download queues and restart download if necessary
        
        path (str) - path to check.  If it matches the next path in the upload
            queue, drop the next entry and reprocess the queue
        requested (bool) - whether a put request has been sent for this upload
        """
        if not requested and self.uploadqueue != [] and self.uploadqueue[-1].starttime == None and \
           path == os.path.dirname(self.uploadqueue[-1].serverpath):
            self.log.warning('Problem with path, skipping upload of %s' % path)
            self.uploadqueue.pop()
            self._put()
            return 0
        elif requested and path in self.currentuploads:
            self.log.warning('Problem with path, skipping upload of %s' % path)
            del self.currentuploads[path]
            self._put()
            return 0
        return 1
        
    def restorequeues(self, filename = '', starttransfers = False, lock = True):
        """Restore the previously saved upload and download queues
        
        filename (str) - the name of the file (less the extension) where the 
            queues and caches are stored
        starttrasnfers (bool) - whether to immediately start the transfers 
            after restoring the queues
            
        Note: This requires overwriting the current upload and download
        queues, as well as the current file and filelist caches
        """
        self.acquirelock(lock)
        if filename == '':
            filename = self.host
        filelistcache = file('%s.wflc' % filename, 'rb')
        filecache = file('%s.wfc' % filename, 'rb')
        uploadqueue = file('%s.wuq' % filename, 'rb')
        downloadqueue = file('%s.wdq' % filename, 'rb')
        self.filelists = cPickle.load(filelistcache)
        self.files = cPickle.load(filecache)
        self.uploadqueue = cPickle.load(uploadqueue)
        self.downloadqueue = cPickle.load(downloadqueue)
        self.log.info('Queues and file caches restored')
        if starttransfers:
            self._get()
            self._put()
        self.releaselock(lock)
        return 0
        
    def savequeues(self, filename = '', lock = True):
        """Save the upload and download queues so they can be restored later
        
        filename (str) - the name of the file (less the extension) where the queues
            and caches should be stored
        
        In order for the queues to be restored and work correctly, the file
        and filelist caches must be saved as well"""
        self.acquirelock(lock)
        if filename == '':
            filename = self.host
        filelistcache = file('%s.wflc' % filename, 'wb')
        filecache = file('%s.wfc' % filename, 'wb')
        uploadqueue = file('%s.wuq' % filename, 'wb')
        downloadqueue = file('%s.wdq' % filename, 'wb')
        cPickle.dump(self.filelists, filelistcache)
        cPickle.dump(self.files, filecache)
        cPickle.dump(self.uploadqueue, uploadqueue)
        cPickle.dump(self.downloadqueue, downloadqueue)
        self.log.info('Queues and file caches saved')
        self.releaselock(lock)
        return 0
        
    def userid(self, user):
        """Return the userid for given object, if possible
        
        user - if integer, probably the userid itself, so return it
            if wireduser, return the id
            if string, see if there is anyone with that nick on the server,
                and return the nick for that person
            otherwise return None
        """
        if isinstance(user, int):
            return user
        if isinstance(user, wireduser):
            return user.id
        if isinstance(user, str):
            # If more than one user has the given nick, this will probably
            # pick one randomly.  This is just here for ease of use on the
            # command line.  Real programs should always pass an int or
            # a wireduser object
            users = dict([(f.nick, f.id) for f in self.users])
            if user in users:
                return users[user]
        return None
            
    ### Functions that send commands to server
    
    ## Functions that affect this connection

    def changeicon(self, icon, lock = True):
        """Change icon
        
        icon (int) - icon number to which to change
        """
        self.acquirelock(lock)
        self.log.info('Changing icon to %s' % icon)
        self._send("ICON %s\04" % icon)
        self.releaselock(lock)
        return 0

    def changenick(self, nick, lock = True):
        """Change nick
        
        nick (str) - nick to which to change
        """
        self.acquirelock(lock)
        self.log.info('Changing nick to %s' % nick)
        self._send("NICK %s\04" % nick)
        self.releaselock(lock)
        return 0
        
    def connect(self, lock = True):
        """Connect to the Wired Server"""
        self.acquirelock(lock)
        # Initialize a bunch of connection related variables
        self._resetfilestructures()
        # Figure out connection string
        osname = ''
        self.passwordhash = ''
        if self.appname == '':
            self.appname = 'py-wire/%s' % self.version
        libversion = '(py-wire/%s; tlslite/%s)' % (self.version, tlsversion)
        if os.name == 'posix':
            osname = '; '.join(os.popen('uname -srm','r').read()[:-1].split())
        elif os.name == 'nt':
            wininfo = sys.getwindowsversion()
            if wininfo[3] == 1:
                osname = 'Windows 9x'
            elif wininfo[3] == 2:
                osname = 'Windows NT'
            else:
                osname = 'Windows'
            osname += '; %s.%s; i386' % (wininfo[0], wininfo[1])
        else:
            osname = '%s; Unknown; Unknown' % sys.platform
        self.clientversionstring = "%s (%s) %s" % (self.appname, osname, libversion)
        # Determine password hash and connect 
        if self.password != '':
            self.passwordhash = sha.new(self.password.encode('utf8','ignore')).hexdigest()
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host,self.port))
            self.tlssocket = TLSConnection(self.socket)
            self.tlssocket.handshakeClientCert()
            self._send("HELLO\04")
            self.connectionresponse = self.tlssocket.recv(self.buffersize)
            if self.connectionresponse[:3] != '200':
                self.log.error('You have been banned from %s' % self.host)
                self.socket = None
                self.tlssocket = None
                self.releaselock(lock)
                return 1
            self.log.info('Connected to %s' % self.host)
            # Add miscellaneous info and login
            self.changenick(self.nick, False)
            self.changeicon(self.icon, False)
            self.log.debug('Sending client string: %s' % self.clientversionstring)
            self._send("CLIENT %s\04" % self.clientversionstring)
            self.log.debug('Logging in as: %s' % self.login)
            self._send("USER %s\04" % self.login)
            self.log.debug('Sending password')
            self._send("PASS %s\04" % self.passwordhash)
            self.loginresponse = self.tlssocket.recv(self.buffersize)
            if self.loginresponse[:3] != '201':
                self.log.error('Login as %s not successful' % self.login)
                self.socket = None
                self.tlssocket = None
                self.releaselock(lock)
                return 1
            self.log.info('Logged into %s as %s' % (self.host, self.login))
            # It's all good, so get privileges and the user list for the public chat
            self.getprivileges(False)
            self.getuserlist(1, False)
        except (socket.error, TLSError, ValueError):
            self.log.error("Couldn't connect or login to server: %s %s %s" % sys.exc_info())
            self.releaselock(lock)
            return 1
        self.releaselock(lock)
        thread.start_new_thread(self._listen,())
        thread.start_new_thread(self._pingserver,())
        return 0
        
    def getprivileges(self, lock = True):
        """Get privileges for this connection"""
        self.acquirelock(lock)
        success = True
        if not self.requested['privileges']:
            self.requested['privileges'] = True
            self.log.info('Requesting privileges')
            self._send("PRIVILEGES\04")
        else:
            self.log.warning('Already requested privileges')
            success = False
        self.releaselock(lock)
        return 0
        
    ## Account Functions
    
    def createaccount(self, name, password, group, privileges, lock = True):
        """Create a new user account
        
        name (str) - name of account
        password (str) - password for account
        group (str) - group in which the account should be
        privileges (wireprivileges) - privileges for account
        """
        self.acquirelock(lock)
        if self.privileges.createaccounts:
            self.log.info('Creating new user: %s' % name)
            self._send("CREATEUSER %s\x1c%s\x1c%s\x1c%s\04" % (name, password, group, privileges))
        else:
            self.log.warning('You don\'t have the privileges to create a new account')
        self.releaselock(lock)
        return int(not self.privileges.createaccounts)
        
    def creategroup(self, name, privileges, lock = True):
        """Create a new group
        
        name (str) - name of group
        privileges (wireprivileges) - privileges for group
        """
        self.acquirelock(lock)
        if self.privileges.createaccounts:
            self.log.info('Creating new group: %s' % name)
            self._send("CREATEGROUP %s\x1c%s\04" % (name, privileges))
        else:
            self.log.warning('You don\'t have the privileges to create a group')
        self.releaselock(lock)
        return int(not self.privileges.createaccounts)
        
    def deleteaccount(self, name, lock = True):
        """Delete a user account
        
        name (str) - name of account to delete
        """
        self.acquirelock(lock)
        if self.privileges.deleteaccounts:
            self.log.info('Deleting user: %s' % name)
            self._send("DELETEUSER %s\04" % name)
        else:
            self.log.warning('You don\'t have the privileges to delete an account')
        self.releaselock(lock)
        return int(not self.privileges.deleteaccounts)
        
    def deletegroup(self, name, lock = True):
        """Delete a group
        
        name (str) - name of group to delete
        """
        self.acquirelock(lock)
        if self.privileges.deleteaccounts:
            self.log.info('Deleting group: %s' % name)
            self._send("DELETEGROUP %s\04" % name)
        else:
            self.log.warning('You don\'t have the privileges to delete an account')
        self.releaselock(lock)
        return int(not self.privileges.deleteaccounts)
        
    def editaccount(self, account, lock = True):
        """Edit a user account specification
        
        account (wireaccount) - update the server using the information in this
            account
        """
        self.acquirelock(lock)
        if self.privileges.editaccounts:
            self.log.info('Editing user account: %s' % account.name)
            self._send("EDITUSER %s\04" % unicode(account))
        else:
            self.log.warning('You don\'t have the privileges to edit users')
        self.releaselock(lock)
        return int(not self.privileges.editaccounts)
        
    def editgroup(self, account, lock = True):
        """Edit a group account specification

        account (wireaccount) - update the server using the information in this
            group account
        """
        self.acquirelock(lock)
        if self.privileges.editaccounts:
            self.log.info('Editing group account: %s' % account.name)
            self._send("EDITGROUP %s\04" % unicode(account))
        else:
            self.log.warning('You don\'t have the privileges to edit groups')
        self.releaselock(lock)
        return int(not self.privileges.editaccounts)
        
    def getaccounts(self, lock = True):
        """Get a list of user accounts"""
        self.acquirelock(lock)
        success = False
        if self.privileges.editaccounts and not self.requested['accountlist']:
            self.log.info('Getting list of user accounts')
            self.requested['accountlist'] = True
            self.accounts = {}
            self._send("USERS\04")
            success = True
        elif self.requested['accountlist']:
            self.log.warning('You already have an outstanding request for the list of user accounts')
        else:
            self.log.warning('You don\'t have the privileges to get a list of user accounts')
        self.releaselock(lock)
        return int(not success)
        
    def getaccountspec(self, name, lock = True):
        """Get account specification for user
        
        name (str) - name of account for which to get specification
        """
        self.acquirelock(lock)
        success = False
        if self.privileges.editaccounts and name not in self.requested['readuser']:
            self.log.info('Requesting spec for user: %s' % name)
            self.requested['readuser'].append(name)
            self._send("READUSER %s\04" % name)
            success = True
        elif name in self.requested['readuser']:
            self.log.warning('You already have an outstanding request for a spec for this user')
        else:
            self.log.warning('You don\'t have the privileges to get a user specification')
        self.releaselock(lock)
        return int(not success)
        
    def getgroups(self, lock = True):
        """Get a list of user groups"""
        self.acquirelock(lock)
        success = False
        if self.privileges.editaccounts and not self.requested['grouplist']:
            self.groups = {}
            self.log.info('Getting list of user groups')
            self.requested['grouplist'] = True
            self._send("GROUPS\04")
            success = True
        elif self.requested['grouplist']:
            self.log.warning('You already have an outstanding request for the list of group accounts')
        else:
            self.log.warning('You don\'t have the privileges to get a list of group accounts')
        self.releaselock(lock)
        return int(not success)
        
    def getgroupspec(self, name, lock = True):
        """Get account specification for group
        
        name (str) - name of group account for which to get specification
        """
        self.acquirelock(lock)
        success = False
        if self.privileges.editaccounts and name not in self.requested['readgroup']:
            self.log.info('Requesting spec for group: %s' % name)
            self.requested['readgroup'].append(name)
            self._send("READGROUP %s\04" % name)
            success = True
        elif name in self.requested['readgroup']:
            self.log.warning('You already have an outstanding request for a spec for this group')
        else:
            self.log.warning('You don\'t have the privileges to get a group specification')
        self.releaselock(lock)
        return int(not success)
        
    ## Chat Functions
    
    def actionchatmessage(self, chatid, message, lock = True):
        """Send an action message to a chat
        
        chatid (int) - id of chat to which to send message
        message (str) - action chat message to send
        """
        self.acquirelock(lock)
        self.log.info('Sending action message to chat %s: %s' % (chatid, message))
        self._send("ME %s\x1c%s\04" % (chatid, message))
        self.releaselock(lock)
        return 0

    def broadcast(self, message, lock = True):
        """Send a message to all users
        
        message (str) - broadcast message to send
        """
        self.acquirelock(lock)
        if self.privileges.broadcast:
            self.log.info('Sending broadcast message: %s' % message)
            self._send("BROADCAST %s\04" % message)
        else:
            self.log.warning('You don\'t have the privileges to send a broadcast message')
        self.releaselock(lock)
        return int(not self.privileges.broadcast)
        
    def chatmessage(self, chatid, message, lock = True):
        """Send a message to a chat
        
        chatid (int) - id of chat to which to send message
        message (str) - broadcast message to send
        """
        self.acquirelock(lock)
        self.log.info('Sending message to chat %s: %s' % (chatid, message))
        self._send("SAY %s\x1c%s\04" % (chatid, message))
        self.releaselock(lock)
        return 0
        
    def createprivatechat(self, lock = True):
        """Create a private chat"""
        self.acquirelock(lock)
        self.requested['privatechat'] += 1
        self.log.info('Creating Private Chat')
        self._send("PRIVCHAT\04")
        self.releaselock(lock)
        return 0
        
    def declineprivatechat(self, chatid, lock = True):
        """Decline a private chat
        
        chatid (int) - id of chat to which to decline joining
        """
        self.acquirelock(lock)
        self.log.info('Declining private chat %s' % chatid)
        self._send("DECLINE %s\04" % chatid)
        del self.privatechatinvites[chatid]
        self.releaselock(lock)
        return 0
        
    def getuserlist(self, chatid, lock = True):
        """Get userlist for chat
        
        chatid (int) - id of chat to which to get user list
        """
        self.acquirelock(lock)
        chatid = int(chatid)
        success = True
        if chatid not in self.requested['userlist']:
            # create or empty the list of users for this chat
            self.chats[chatid] = []
            self.requested['userlist'].append(chatid)
            self.log.info('Requesting User list for chat %s' % chatid)
            self._send("WHO %s\04" % chatid)
        else:
            self.log.warning('You already have or have requested the list of users for this chat')
            success = False
        self.releaselock(lock)
        return int(not success)
        
    def inviteuser(self, user, chatid, lock = True):
        """Inivite a user to a private chat
        
        user - user to invite
        chatid (int) - id of chat to which to invite user
        """
        self.acquirelock(lock)
        userid = self.userid(user)
        success = False
        if chatid == 1:
            self.log.warning('Can\'t invite users to the public chat')
        elif chatid not in self.chats:
            self.log.warning('Can\'t invite users to a chat in which you are not present')
        else:
            self.log.info('Iniviting %s to chat %s' % (self.users[userid].nick, chatid))
            self._send("INVITE %s\x1c%s\04" % (userid, chatid))
            success = True
        self.releaselock(lock)
        return int(not success)
        
    def joinprivatechat(self, chatid, lock = True):
        """Join a private chat
        
        chatid (int) - id of chat to which to join
        """
        self.acquirelock(lock)
        self.log.info('Joining private chat %s' % chatid)
        self._send("JOIN %s\04" % chatid)
        self.getuserlist(chatid, False)
        del self.privatechatinvites[chatid]
        self.releaselock(lock)
        return 0

    def leavechat(self, chatid, lock = True):
        """Leave a chat
        
        chatid (int) - id of chat to which to leave
        """
        self.acquirelock(lock)
        self.log.info('Leaving chat %s' % chatid)
        for userid in self.chats[chatid]:
            self.log.debug('Removing chat %s from user %s' % (chatid, userid))
            self.users[userid].removechat(chatid)
        self._send("LEAVE %s\04" % chatid)
        self.log.debug('Removing chat %s' % chatid)
        del self.chats[chatid]
        if chatid == 1:
            # I don't believe that the server will disconnect you if you send
            # it a leave message with a chatid of 1, but you should only be 
            # doing this if you want to leave the server
            self.log.info('Left public chat, disconnecting from server')
            try:
                self.tlssocket.close()
            except SyntaxError:
                pass
            self.socket.close()
        self.releaselock(lock)
        return 0
        
    def privatemessage(self, user, message, lock = True):
        """Send a private message to a user
        
        user - user to which to send message
        message (str) - message to send to user
        """
        self.acquirelock(lock)
        userid = self.userid(user)
        self.log.info('Sending message to %s: %s' % (self.users[userid].nick, message))
        self._send("MSG %s\x1c%s\04" % (userid, message))
        self.releaselock(lock)
        return 0
        
    ## File Functions
    
    def createfolder(self, path, lock = True):
        """Create a new folder
        
        path (str) - path at which to create folder
        """
        self.acquirelock(lock)
        failure = True
        if not self.privileges.createfolders:
            self.log.warning('You don\'t have the privileges to create folders')
        elif path in self.files or path in self.filelists:
            self.log.warning('%s already exists on the server' % path)
        else:
            # Since the server doesn't respond to a successful issue of this
            # command, we have to assume it succeeds and add the necessary entries
            # to files and filelists
            self.filelists[path] = {'revision':0, 'freeoctets':0}
            self.files[path] = wirepath(path, 1, 0)
            serverdir = os.path.dirname(path)
            if serverdir in self.files:
                self.files[path].type = self.files[serverdir].type
            if serverdir in self.filelists:
                self.filelists[path]['freeoctets'] = self.filelists[serverdir]['freeoctets']
            self.log.info('Creating new folder: %s' % path)
            self._send("FOLDER %s\04" % path)
            failure = False
        self.releaselock(lock)
        return int(failure)
        
    def deletepath(self, path, lock = True):
        """Delete a file/folder
        
        path (str) - path to delete, all deletes are recursive
        """
        self.acquirelock(lock)
        if self.privileges.deletefiles:
            self.log.info('Deleting path: %s' % path)
            self.forgetpath(path, False)
            self._send("DELETE %s\04" % path)
        else:
            self.log.warning('You don\'t have the privileges to delete files/folders')
        self.releaselock(lock)
        return int(not self.privileges.deletefiles)
        
    def download(self, serverpath, hostpath, lock = True):
        """Add a file or folder to the upload queue
        
        serverpath (str) - remote path to download
        hostpath (str) - local path at which to store downloaded files
        """
        self.acquirelock(lock)
        self.log.debug('download called with (%s,%s,%s)' % (serverpath, hostpath, lock))
        failure = True
        hostpath, serverpath = self.normpaths(hostpath, serverpath)
        if not self.privileges.download:
            self.log.warning("You don't have the privileges to download files/folders")
        elif not os.path.exists(os.path.dirname(hostpath)):
            self.log.warning("The folder you are are trying to download into doesn't exist")
        else:
            self.log.info('Adding %s to download queue' % serverpath)
            self.downloadqueue.insert(0,wiredownload(serverpath,hostpath))
            self._get()
            failure = False
        self.releaselock(lock)
        return int(failure)
        
    def getfileinfo(self, path, lock = True):
        """Get info for file
        
        path (str) - path about which to get info
        """
        self.acquirelock(lock)
        success = True
        if path not in self.requested['fileinfo']:
            self.requested['fileinfo'].append(path)
            self.log.info('Requesting info for %s' % path)
            self._send("STAT %s\04" % path)
        else:
            self.log.debug('Already getting info for that file')
            success = False
        self.releaselock(lock)
        return int(not success)
        
    def getfilelist(self, path, lock = True):
        """Get filelist for path"""
        self.acquirelock(lock)
        failure = True
        if path not in self.requested['filelists']:
            self.requested['filelists'].append(path)
            if path not in self.filelists:
                self.filelists[path] = {'revision':0, 'freeoctets':0}
            else:
                self.filelists[path]['revision'] += 1
            self.log.info('Requesting file list for %s' % path)
            self._send("LIST %s\04" % path)
            failure = False
        else:
            self.log.warning('You already have an outstanding request to get this filelist')
        self.releaselock(lock)
        return int(failure)
        
    def movepath(self, pathfrom, pathto, lock = True):
        """Move a file/folder
        
        pathfrom (str) - current location of path to move
        pathto (str) - location to which to move path
        """
        self.acquirelock(lock)
        if self.privileges.movefiles:
            self.log.info('Moving path %s to %s' % (pathfrom, pathto))
            self.forgetpath(pathfrom, False)
            self._send("MOVE %s\x1c%s\04" % (pathfrom, pathto))
        else:
            self.log.warning('You don\'t have the privileges to move files/folders')
        self.releaselock(lock)
        return int(not self.privileges.movefiles)
        
    def searchfiles(self, query, lock = True):
        """Search for files with names containing query
        
        query (str) - search query (server will return all files containing 
            this query as a substring, I think)
        """
        self.acquirelock(lock)
        success = True
        if query not in self.requested['searchlists']:
            self.requested['searchlists'].append(query)
            self.log.info('Searching for paths containing %s' % query)
            self.searches[query] = {}
            self._send("SEARCH %s\04" % query)
        else:
            self.log.debug('Already searching with that query')
            success = False
        self.releaselock(lock)
        return int(not success)
        
    def upload(self, hostpath, serverpath, lock = True):
        """Add a file or folder to the upload queue
        
        hostpath (str) - local path to upload
        serverpath (str) - remote path at which to store uploaded files
        """
        self.acquirelock(lock)
        self.log.debug('upload called with (%s,%s,%s)' % (hostpath, serverpath, lock))
        failure = True
        hostpath, serverpath = self.normpaths(hostpath, serverpath)
        if not self.privileges.upload:
            self.log.warning("You don't have the privileges to upload files/folders")
        elif not os.path.exists(hostpath):
            self.log.warning("You can't upload a file or folder that doesn't exist")
        else:
            self.log.info('Adding %s to upload queue' % hostpath)
            self.uploadqueue.insert(0,wireupload(hostpath, serverpath))
            self._put()
            failure = False
        self.releaselock(lock)
        return int(failure)
        
    ## News Functions
    
    def clearnews(self, lock = True):
        """Clear the news"""
        self.acquirelock(lock)
        if self.privileges.clearnews:
            self.log.info('Clearing the news')
            self._send("CLEARNEWS\04")
            self.news = []
        else:
            self.log.warning('You don\'t have the privilages to clear the news')
        self.releaselock(lock)
        return int(not self.privileges.clearnews)
        
    def getnews(self, lock = True):
        """Get news"""
        self.acquirelock(lock)
        success = True
        if not self.requested['news']:
            self.requested['news'] = True
            self.log.info('Requesting news')
            # Empty the news so no duplicates appear
            self.news = []
            self._send("NEWS\04")
        else:
            self.log.debug('Already requested news')
            success = False
        self.releaselock(lock)
        return int(not success)
        
    def postnews(self, message, lock = True):
        """Post a new news article
        
        message (str) - message to post to the news
        """
        self.acquirelock(lock)
        if self.privileges.postnews:
            self.log.info('Posting a new news article: %s' % message)
            self._send("POST %s\04" % message)
        else:
            self.log.warning('You don\'t have the privileges to post to the news')
        self.releaselock(lock)
        return int(not self.privileges.postnews)
        
    ## User Functions

    def getuserinfo(self, user, lock = True):
        """Get info on a user
        
        user - user about which to get info"""
        self.acquirelock(lock)
        userid = self.userid(user)
        success = False
        if self.privileges.getuserinfo and userid not in self.requested['userinfo']:
            self.requested['userinfo'].append(userid)
            self.log.info('Getting info for %s' % self.users[userid].nick)
            self._send("INFO %s\04" % userid)
            success = True
        elif userid in self.requested['userinfo']:
            self.log.warning('You already have an outstanding request for this user\'s info')
        else:
            self.log.warning('You don\'t have the privileges to get info on users')
        self.releaselock(lock)
        return int(not success)

    def kickuser(self, user, message, lock = True):
        """Kick a user
        
        user - user to kick
        message (str) - message to display when kicking user
        """
        self.acquirelock(lock)
        userid = self.userid(user)
        if self.privileges.kickusers:
            self.log.info('Kicking user %s with comment: %s' % (self.users[userid].nick, message))
            self._send("KICK %s\x1c%s\04" % (userid, message))
        else:
            self.log.warning('You don\'t have the privileges to kick users')
        self.releaselock(lock)
        return int(not self.privileges.kickusers)
        
    def banuser(self, user, message, lock = True):
        """Ban a user temporarily
        
        user - user to kick
        message (str) - message to display when banning user
        """
        self.acquirelock(lock)
        userid = self.userid(user)
        if self.privileges.banusers:
            self.log.info('Banning user %s with comment: %s' % (self.users[userid].nick, message))
            self._send("BAN %s\x1c%s\04" % (userid, message))
        else:
            self.log.warning('You don\'t have the privileges to kick users')
        self.releaselock(lock)
        return int(not self.privileges.banusers)
        
    ### Called on responses from server
    
    ## 2xx Informational
    
    def gotpong(self, args):
        """Received pong response (202)"""
        if self.requested['pong']:
            self.log.debug('Received pong in response to ping')
            self.requested['pong'] = False
            return 0
        self.log.warning('Received unrequested pong')
        return 1
        
    ## 3xx Chat, News, Private Messages
        
    def gotchat(self, args):
        """Received chat message (300)"""
        chatid, userid = map(int,args[:2])
        if chatid in self.chats and userid in self.users:
            self.log.info('Received message in chat %s from %s: %s' % (chatid, self.users[userid].nick,args[2]))
        else:
            self.log.warning('Received chat message from unknown user or in unknown chat')
        return 0
        
    def gotactionchat(self, args):
        """Received action chat message (301)"""
        chatid, userid = map(int,args[:2])
        if chatid in self.chats and userid in self.users:
            self.log.info('Received action message in chat %s from %s: %s' % (chatid, self.users[userid].nick,args[2]))
        else:
            self.log.warning('Received action chat message from unknown user or in unknown chat')
        return 0
        
    def gotclientjoin(self, args):
        """Received client join (302)"""
        chatid, userid = map(int,args[:2])
        if chatid == 1 and userid not in self.users:
            self.log.info('%s joined server' % args[5])
            self.users[userid] = wireuser(userid,args[2],args[3],args[4],args[5],args[6],args[7])
        if chatid in self.chats:
            self.log.debug('Adding chat %s to user %s' % (chatid, userid))
            self.users[userid].addchat(chatid)
            self.log.debug('Adding user %s to chat %s' % (userid, chatid))
            self.chats[chatid].append(userid)
            return 0
        self.log.warning('Received a client join message for a chat we are not in')
        return 1

    def gotclientleave(self, args):
        """Received client leave (303)"""
        chatid, userid = map(int,args[:2])
        success = True
        if chatid in self.chats and userid in self.chats[chatid]:
            self.log.debug('Removing user %s from chat %s' % (userid, chatid))
            self.chats[chatid].remove(userid)
        elif chatid in self.chats:
            self.log.warning('Received a client leave message for a user not in the chat')
            success = False
        else:
            self.log.warning('Received a client leave message for a chat we are not in')
            success = False
        if userid in self.users and chatid in self.users[userid].chats:
            self.log.debug('Removing chat %s from user %s' % (chatid, userid))
            self.users[userid].removechat(chatid)
        elif userid in self.users: 
            self.log.warning('Received a client leave message for a user not in the chat')
            success = False
        else:
            self.log.warning('Received a client leave message for an unknown user')
            success = False
        if chatid == 1 and userid in self.users:
            for id in [i for i in self.users[userid].chats if id in self.chats]:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].remove(userid)
            self.log.info('%s left server' % self.users[userid].nick)
            del self.users[userid]
        return int(not success)
        
    def gotstatuschange(self, args):
        """Received status change for user (304)"""
        userid = int(args[0])
        if userid in self.users:
            user = self.users[userid].updatestatus(args[1], args[2], args[3], args[4])
            self.log.debug('User %s status has changed' % userid)
            return 0
        self.log.warning('Got status change for user not on server')
        return 1
        
    def gotprivatemessage(self, args):
        """Received private message (305)"""
        userid = int(args[0])
        if userid in self.users:
            self.log.info('Received private message from %s: %s' % (self.users[userid].nick,args[1]))
        else:
            self.log.warning('Received private message from unknown user')
        return 0
        
    def gotclientkicked(self, args):
        """Received client kicked (306)"""
        userid, kickerid = map(int, args[:2])
        if userid in self.users:
            for id in self.users[userid].chats:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].remove(userid)
            self.log.info('User %s was kicked by %s: %s' % (self.users[userid].nick, self.users[kickerid].nick, args[2]))
            del self.users[userid]
            return 0
        self.log.warning('Got client kicked message change for user not on server')
        return 1
        
    def gotclientbanned(self, args):
        """Received client banned (307)"""
        userid, kickerid = map(int, args[:2])
        if userid in self.users:
            for id in self.users[userid].chats:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].remove(userid)
            self.log.info('User %s was banned by %s: %s' % (userid, self.users[kickerid].nick, args[2]))
            del self.users[userid]
            return 0
        self.log.warning('Got client banned message change for user not on server')
        return 1
        
    def gotuserinfo(self, args):
        """Received user info (308)"""
        userid = int(args[0])
        if userid in self.requested['userinfo'] and userid in self.users:
            self.log.info('Received info for user %s' % userid)
            downloads, uploads = {}, {}
            if args[13] != "":
                for d in args[13].split('\x1d'):
                    dl = d.split('\x1e')
                    downloads[dl[0]] = wiretransfer(dl[0], dl[1], dl[2], dl[3])
            if args[14] != "":
                for u in args[14].split('\x1d'):
                    ul = u.split('\x1e')
                    uploads[ul[0]] = wiretransfer(ul[0], ul[1], ul[2], ul[3])
            self.users[userid].updatestatus(args[1], args[2], args[3], args[4])         
            self.users[userid].updateinfo(args[5], args[6], args[7])
            self.users[userid].updateextendedinfo(args[8], args[9], args[10], args[11], args[12], downloads, uploads)
            self.requested['userinfo'].remove(userid)
            return 0
        self.log.warning('Received user info for user not on server')
        return 1

    def gotbroadcast(self, args):
        """Received broadcast message (309)"""
        userid = int(args[0])
        if userid in self.users:
            self.log.info('Received broadcast message from %s: %s' % (self.users[userid].nick,args[1]))
        elif userid == 0:
            self.log.info('Server admin has broadcast a message: %s' % args[1])
        else:
            self.log.warning('Received broadcast message from unknown user')
        return 0
    
    def gotuserlist(self, args):
        """Received user info (310)"""
        chatid, userid = map(int, args[:2])
        if chatid in self.requested['userlist']:
            if userid not in self.users:
                if chatid == 1:
                    self.log.info('Currently Online: %s' % args[5])
                    self.users[userid] = wireuser(userid,args[2],args[3],args[4],args[5],args[6],args[7],args[8])
                else:
                    self.log.warning('Got userlist for private chat %s with unknown user id: %s' % (args, userid))
                    return 1
            self.log.debug('Adding chat %s to user %s' % (chatid,userid))
            self.users[userid].addchat(chatid)
            self.log.debug('Adding user %s to chat %s' % (userid,chatid))
            self.chats[chatid].append(userid)
            return 0
        self.log.warning('Received unrequested userlist')
        return 1
            
    def gotuserlistdone(self, args):
        """Finished receiving userlist (311)"""
        chatid = int(args[0])
        if chatid in self.requested['userlist']:
            self.log.info('User List Finished for Chat %s' % chatid)
            self.requested['userlist'].remove(chatid)
            return 0
        self.log.warning('Finished receiving unrequested userlist')
        return 1
        
    def gotnews(self,args):
        """Received news article (320)"""
        if self.requested['news']:
            self.news.append(wirenewspost(args[0], args[1], args[2]))
            self.log.info('%s' % unicode(self.news[-1]))
            return 0
        self.log.warning('Received unrequested news article')
        return 1
        
    def gotnewsdone(self, args):
        """Finished receiving news (321)"""
        if self.requested['news']:
            self.log.debug('Finished receiving news')
            self.requested['news'] = False
            return 0
        self.log.warning('Finished receiving unrequested news')
        return 1
        
    def gotnewsposted(self, args):
        """New news article posted (322)"""
        self.news.insert(0, wirenewspost(args[0], args[1], args[2]))
        self.log.info('New News Article: %s' % unicode(self.news[0]))
        return 0
        
    def gotprivatechatcreated(self, args):
        """Received private chat created (330)"""
        if self.requested['privatechat'] > 0:
            self.log.info('Private Chat Created, id: %s' % args[0])
            self.getuserlist(int(args[0]), False)
            self.requested['privatechat'] -= 1
        else:
            self.log.warning('Got unrequested private chat created message')
        return 0
        
    def gotprivatechatinvite(self, args):
        """Received private chat invite (331)"""
        chatid, userid = map(int, args[:2])
        if userid in self.users:
            self.log.info('Received private chat invite from %s' % self.users[userid].nick)
            self.privatechatinvites[chatid] = {'chatid':chatid, 'user':self.users[userid]}
            return 0
        self.log.warning('Received private chat invite from unknown user')
        return 0
        
    def gotprivatechatdeclined(self, args):
        """Received private chat declined (332)"""
        chatid, userid = map(int, args[:2])
        if chatid in self.chats and userid in self.users:
                self.log.info('%s declined to enter the private chat' % self.users[userid].nick)
        else:
            self.log.warning('Received Private Chat Declined message for a chat in which you are not present')
        return 0
        
    ## 4xx Files, Transfers
    
    def gottransferready(self, args):
        """Received transfer ready (400)"""
        path = args[0]
        if path in self.currentdownloads:
            if int(args[1]) ==  self.currentdownloads[path].offset:
                self.log.info('Your download of %s is ready' % path)
                if path in self.requested['downloads']:
                    self.requested['downloads'].remove(path)
                thread.start_new_thread(self._receivefile, (self.currentdownloads[path], args[1], args[2]))
            else:
                self.log.error('Offset offered doesn\'t match offset requested for download of ' % path)
        elif path in self.currentuploads:
            self.log.info('Your upload of %s is ready' % path)
            if path in self.requested['uploads']:
                self.requested['uploads'].remove(path)
            thread.start_new_thread(self._sendfile, (self.currentuploads[path], args[1], args[2]))
        else:
            self.log.warning('Received transfer ready for unrequested upload or download')
            return 1
        return 0    
            
    def gottransferqueued(self, args):
        """Received transfer queued (401)"""
        path = args[0]
        if path in self.currentdownloads:
            self.log.info('Your download of "%s" is at position %s in the queue' % (path, args[1]))
        elif path in self.currentuploads:
            self.log.info('Your upload of "%s" is at position %s in the queue' % (path, args[1]))
        else:
            self.log.warning('Received transfer ready for unrequested transfer')
            return 1
        return 0
            
    def gotfileinfo(self, args):
        """Received file info (402)"""
        path = args[0]
        if path in self.requested['fileinfo']:
            self.log.info('Got extended file info for %s' % path)
            if path in self.files:
                del self.files[path]
            self.requested['fileinfo'].remove(path)
            self.files[path] = wirepath(path, args[1], args[2])
            self.files[path].updateinfo(args[1], args[2], args[3], args[4], args[5])
            if self.downloadqueue != [] and path == self.downloadqueue[-1].serverpath:
                # This path was mostly likely requested inside of _get because
                # the necessary information wasn't in the cache.  Now that it
                # is in the cache, call _get to complete the download
                self._get()
            elif self.uploadqueue != [] and path == os.path.dirname(self.uploadqueue[-1].serverpath):
                self._put()
            return 0
        self.log.warning('Received unrequested file info')
        return 1
        
    def gotfilelist(self, args):
        """Received file in filelist (410)"""
        folder, filename = os.path.split(args[0])
        path = args[0]
        if folder in self.requested['filelists']:
            self.log.info('Got info for %s' % path)
            if path not in self.filelists:
                self.files[path] = wirepath(path, args[1], args[2])
            else:
                self.files[path].updateinfo(args[1], args[2])
            self.files[path].revision = self.filelists[os.path.dirname(path)]['revision']
            return 0
        self.log.warning('Received unrequested filelist item')
        return 1
            
    def gotfilelistdone(self, args):
        """Finished receiving filelist (411)"""
        folder = args[0]
        if folder in self.requested['filelists']:
            self.log.info('Filelist finished for %s' % folder)
            self.requested['filelists'].remove(folder)
            self.filelists[folder]['freeoctets'] = int(args[1])
            for fil in [f for f in self.files if os.path.dirname(f) == folder and \
               self.files[f].revision != self.filelists[folder]['revision']]:
                    del self.files[fil]
            # If this path was in either the download or upload queue, it was
            # probably called by _get or _put, so call those functions now that
            # the information requested is available
            if self.downloadqueue != [] and folder == self.downloadqueue[-1].serverpath:
                self._get()
            elif self.uploadqueue != [] and folder == os.path.dirname(self.uploadqueue[-1].serverpath):
                self._put()
            return 0        
        self.log.warning('Finished receiving unrequested filelist')
        return 1
        
    def gotsearchlist(self, args):
        """Received file matching search info (420)"""
        path = args[0]
        if self.requested['searchlists'] != []:
            self.log.info('Got search reponse: %s' % path)
            if path not in self.filelists:
                self.files[path] = wirepath(path, args[1], args[2])
            else:
                self.files[path].updateinfo(args[1], args[2])
            self.searches[self.requested['searchlists'][0]][path] = self.files[path]
            return 0
        self.log.warning('Received unrequested searchlist item')
        return 1
            
    def gotsearchlistdone(self, args):
        """Finished receiving search list (421)"""
        if self.requested['searchlists'] != []:
            self.log.info('Finished getting search reponse')
            self.requested['searchlists'].pop(0)
            return 0        
        self.log.warning('Finished receiving unrequested searchlist')
        return 1
        
    ## 5xx Errors
        
    def gotcommandfailed(self, args):
        """Received an undefined internal error prevented your command from completing (500)"""
        self.log.error('An undefined internal error prevented the server from processing your command')
        return 0

    def gotcommandnotrecognized(self, args):
        """Received did not recognize your command (501)"""
        self.log.error('The server did not recognize your command')
        return 0
        
    def gotcommandnotimplemented(self, args):
        """Received command not implemented by server (502)"""
        self.log.error('The command you sent has not been implemented on the server')
        return 0
        
    def gotsyntaxerror(self, args):
        """Received there was a syntax error in your command (503)"""
        self.log.error('There was a syntax error in the command you sent')
        return 0
        
    def gotclientnotfound(self, args):
        """Received client not found (512)"""
        self.log.error('The client you tried to access was not found')
        return 0
        
    def gotaccountnotfound(self,args):
        """Received account not found (513)"""
        if self.requested['readuser'] or self.requested['readgroup']:
            # Unless you send multiple account requests without waiting for a 
            # response from the server, this should work fine
            self.log.error('An account you tried to access/modify/delete was not found, some parameters have been reset')
            self.requested['readuser'] = []
            self.requested['readgroup'] = []
            return 0
        self.log.warning('Got account not found without requested an account')
        return 1
        
    def gotaccountexists(self,args):
        """Received account already exists (514)"""
        self.log.error('The account you tried to create already exists')
        return 0
        
    def gotcannotbedisconnected(self,args):
        """Received cannot be disconnected (515)"""
        self.log.error('The user you tried to kick or ban cannot be disconnected')
        return 0
        
    def gotpermissiondenied(self,args):
        """Received permission denied (516)"""
        self.log.error('You lack the permissions necessary to use this command')
        return 0
        
    def gotfilenotfound(self,args):
        """Received file or directory not found (520)"""
        # Wired doesn't tell you which file was not found, so you have to guess
        # The only time you can guess accurately is if there is only 1
        # outstanding request for information.  Assuming this is true, try to
        # guess which file was requested and reset the related parameters so
        # downloading doesn't get stalled because a directory was moved after 
        # it was put into the download queue.  This is unlikely to happen to
        # uploads, but the code is there just in case
        self.log.error('The file or directory you tried to access was not found')
        requests = sum(map(len,(self.requested['filelists'], self.requested['fileinfo'], 
           self.requested['uploads'], self.requested['downloads'])))
        if requests == 1:
            path = ''
            if self.requested['fileinfo'] != []:
                path = self.requested['fileinfo'].pop(0)
                if self.restartdownloadqueueifpathmatches(path):
                    self.restartuploadqueueifpathmatches(path)
            elif self.requested['filelists'] != []:
                path = self.requested['filelists'].pop(0)
                if self.restartdownloadqueueifpathmatches(path):
                    self.restartuploadqueueifpathmatches(path)
            elif self.requested['downloads'] != []:
                path = self.requested['downloads'].pop(0)
                self.restartdownloadqueueifpathmatches(path, True)
            elif self.requested['uploads'] != []:
                path = self.requested['uploads'].pop(0)
                self.restartuploadqueueifpathmatches(path, True)
        return 0
        
    def gotfileexists(self,args):
        """Received file or directory already exists (521)"""
        self.log.error('The file or directory you tried to create already exists')
        if len(self.requested['uploads']) == 1:
            path = self.requested['uploads'].pop(0)
            self.restartuploadqueueifpathmatches(path, True)
        return 0
        
    def gotchecksummismatch(self,args):
        """Received checksum mismatch (522)"""
        # Checksum mismatches only occur on uploads.  Assuming there is only 1
        # outstanding upload request, and it matches the next file in the upload
        # queue, forget about that file and upload the next one.
        self.log.error('The upload or download cannot start because the two checksums do not match')
        if len(self.requested['uploads']) == 1:
            path = self.requested['uploads'].pop(0)
            self.restartuploadqueueifpathmatches(path, True)
        return 0
    
    ## 6xx Administrative
        
    def gotaccountspec(self, args):
        """Received account specification for user (600)"""
        accountname = args[0]
        if accountname in self.requested['readuser']:
            self.log.info('Got account spec for user: %s' % accountname)
            self.accounts[accountname] = wireaccount(accountname, wireprivileges(args[3:]), args[1], args[2])
            self.requested['readuser'].pop(0)
            return 0
        self.log.warning('Received specification for user without requesting it')
        return 1
    
    def gotgroupspec(self, args):
        """Received account specification for group (601)"""
        accountname = args[0]
        if accountname in self.requested['readgroup']:
            self.log.info('Got account spec for group: %s' % accountname)
            self.groups[accountname] = wireaccount(accountname, wireprivileges(args[1:]))
            self.requested['readgroup'].pop(0)
            return 0
        self.log.warning('Received specification for group without requesting it')
        return 1
        
    def gotprivileges(self,args):
        """Received privileges for this connection (602)"""
        # I think the server might send this mask if you edit your own account
        # or group spec, but I'm not sure.  If that is the case,
        # self.requested['privileges'] has to be removed
        if self.requested['privileges']:
            self.log.debug('Got privileges for this connection')
            self.privileges.update(args)
            self.requested['privileges'] = False
            return 0
        self.log.warning('Received privileges without requesting them')
        return 1
        
    def gotaccountlist(self,args):
        """Received account name (610)"""
        accountname = args[0]
        if self.requested['accountlist']:
            self.log.info('Got account: %s' % accountname)
            if accountname not in self.accounts:
                self.accounts[accountname] = None
                return 0
        self.log.warning('Received account list without requesting it')
        return 1
        
    def gotaccountlistdone(self, args):
        """Finished receiving account list (611)"""
        if self.requested['accountlist']:
            self.log.info('Finished receiving account list')
            self.requested['accountlist'] = False
            return 0
        self.log.warning('Got account list done for already finished account list')
        return 1
        
    def gotgrouplist(self,args):
        """Received group name (620)"""
        accountname = args[0]
        if self.requested['grouplist']:
            self.log.info('Got group %s' % accountname)
            if accountname not in self.groups:
                self.groups[accountname] = None
            return 0
        self.log.warning('Received group list without requesting it')
        return 1
        
    def gotgrouplistdone(self, args):
        """Finished receiving group list (621)"""
        if self.requested['grouplist']:
            self.log.info('Finished receiving group list')
            self.requested['grouplist'] = False
            return 0
        self.log.warning('Got group list done for already finished group list')
        return 1
        
    ## Command Not Recognised
        
    def gotunrecognizedmessage(self, servermessage):
        """Received unrecognized message"""
        self.log.warning('Received unrecognized message from server')
        return 0
