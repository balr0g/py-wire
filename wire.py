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

from ConfigParser import RawConfigParser
import cPickle
import logging
import os
import sha
import socket
import sys
import thread
import time
from tlslite.api import *
from tlslite import __version__ as tlsversion
from UserDict import DictMixin

__version__ = '0.4'

## Miscellaneous functions not related to class wire

def parsewiredtime(timestring):
    """Parse the time given by a Wired into Python's native time format"""
    return time.strptime(timestring[:19],'%Y-%m-%dT%H:%M:%S')

## Data structures used by wire

class wireuser:
    """Information relating to a user on Wired server"""
    def __init__(self, id, isidle, isadmin, icon, nick, login, ip, dnsname = '', status = '', image = None):
        """Initialize user on Wired server
        
        id (int) - id of user
        isidle (bool) - whether the user is currently idle
        isadmin (bool) - whether the user is an admin
        icon (int) - number of user's icon
        nick (str) - nickname of user
        login (str) - name of account user used to login
        ip (str) - IP address of user's connection
        dnsname (str) - reverse DNS lookup for user's IP address
        """
        self.id = int(id)
        self.chats = []
        self.downloads, self.uploads = {}, {}
        self.clientversion, self.ciphername, self.image = None, None, None
        self.cipherbits, self.logintime, self.idletime = None, None, None
        self.updatestatus(isidle, isadmin, icon, nick, status)
        self.updateinfo(login, ip, dnsname)
        self.updateimage(image)
        
    def __unicode__(self):
        transferlist = "Downloads:\n"
        for download in self.downloads:
            transferlist += u"Path: %(path)s Transferred: %(transferred)sB Size: %(size)sB Speed: %(speed)sB/s\n" % download
        transferlist += "\n\nUploads:\n"
        for upload in self.uploads:
            transferlist += u"Path: %(path)s Transferred: %(transferred)sB Size: %(size)sB Speed: %(speed)sB/s\n" % upload
        logintime, idletime = None, None
        if self.logintime != None:
            logintime = time.strftime('%Y-%m-%d %H:%M:%S',self.logintime)
        if self.idletime != None:
            idletime = time.strftime('%Y-%m-%d %H:%M:%S',self.idletime)
        return 'Wired User:\nid=%s \nidle=%s \nadmin=%s \nicon=%s \nnick=%s \nstatus=%s \nlogin=%s \nip=%s \nhost=%s \nclientversion=%s \nciphername=%s \ncipherbits=%s \nlogintime=%s \nidletime=%s \n\n%s' % (self.id, self.isidle, self.isadmin, self.icon, self.nick, self.status, self.login, self.ip, self.dnsname, self.clientversion, self.ciphername, self.cipherbits, logintime, idletime, transferlist)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
    def updatestatus(self, isidle, isadmin, icon, nick, status=''):
        """Update client status
        
        isidle (bool) - whether the user is currently idle
        isadmin (bool) - whether the user is an admin
        icon (int) - number of user's icon
        nick (str) - nickname of user
        status (str) - status message for user
        """
        self.isidle = bool(int(isidle))
        self.isadmin = bool(int(isadmin))
        self.icon = int(icon)
        self.nick = '%s' % nick
        self.status = '%s' % status
        
    def updateimage(self, image):
        """Update client's custom image
        
        image (str) - Base64 encoded string containing image
        """
        if isinstance(image, basestring):
            try:
                self.image = str(image).decode('base64')
            except binascii.Error:
                return 1
            return 0
        return 1
        
    def updateinfo(self, login, ip, dnsname = ''):
        """Update regular client info
        
        login (str) - name of account user used to login
        ip (str) - IP address of user's connection
        dnsname (str) - reverse DNS lookup for user's IP address
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
    def __init__(self, path, type, size, createtime, modifytime):
        """Initialize record of path on server
        
        path (str) - path of file on server
        type (int) - type of path on server (0 = regular file, 1 = regular
            directory, 2 = upload directory, 3 = drop box)
        size (int) - if type=0: size of path in bytes, otherwise number of 
            files in path
        """
        self.path = '%s' % path
        self.createtime, self.modifytime, self.checksum = None, None, None
        self.comment = ''
        self.updateinfo(type, size, createtime, modifytime)
        self.revision = 0
        
    def updateinfo(self, type, size, createtime = None, modifytime = None, checksum = None, comment = ''):
        """Update info for file
        
        type (int) - type of path on server
        size (int) - if type=0: size of path in bytes, otherwise number of 
            files in path
        createtime (str) - time of creation of path, in Wired format
        modifytime (str) - time of last modification to path, in Wired format
        checksum (str) - hexdecimal sha-1 checksum of first 1MB of file
        comment (str) - comment for path
        """
        self.type = int(type)
        self.size = int(size)
        if createtime != None:
            self.createtime = parsewiredtime(createtime)
        if modifytime != None:
            self.modifytime = parsewiredtime(modifytime)
        if checksum != None:
            self.checksum = '%s' % checksum
        self.comment = '%s' % comment
        
    def __unicode__(self):
        createtime, modifytime = None, None
        if self.createtime != None:
            createtime = time.strftime('%Y-%m-%d %H:%M:%S',self.createtime)
        if self.modifytime != None:
            modifytime = time.strftime('%Y-%m-%d %H:%M:%S',self.modifytime)
        return 'Wired File:\npath=%s \ntype=%s \nsize=%s \ncreated=%s \nmodified=%s \nchecksum=%s \ncomment=%s \n' % (self.path, self.type, self.size, createtime, modifytime, self.checksum, self.comment)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wireprivileges(DictMixin):
    """Information on privileges held by user
    
    All privileges can be accessed as attributes, even though they are stored
    in a list."""
    def __init__(self, privileges = None):
        """Initialize privileges for server
        
        privileges (list) - list of values of privileges, see update docstring
        """
        # Privileges are stored in a list
        # They can be access by name as attributes by checking for which
        # position they are in the list through the mapping dictionary
        self.numprivileges = 23
        self.privileges = [0]*self.numprivileges
        self.mapping = {'getuserinfo':0, 'broadcast':1, 'postnews':2, 'clearnews':3,
            'download':4, 'upload':5, 'uploadanywhere':6, 'createfolders':7,
            'alterfiles': 8, 'deletefiles':9, 'viewdropboxes':10, 
            'createaccounts':11, 'editaccounts':12, 'deleteaccounts':13,
            'elevateprivileges':14, 'kickusers':15, 'banusers':16,
            'cannotbekicked':17, 'downloadspeed':18, 'uploadspeed':19, 
            'downloadlimit':20, 'uploadlimit':21, 'changetopic':22}
        self.reversemapping = {}
        for key, value in self.mapping.items():
            self.reversemapping[value] = key
        self.reversemappinglist = []
        for i in range(self.numprivileges):
            self.reversemappinglist.append(self.reversemapping[i])
        if privileges != None:
            self.update(privileges)
            
    def __unicode__(self):
        return "\x1c".join(map(str,(map(int,self.privileges))))
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
    
    def __len__(self):
        return len(self.privileges)
        
    def __contains__(self, item):
        if isinstance(item, basestring):
            return (item in self.mapping)
        elif isinstance(item, int):    
            return (item > 0 and item <= self.numprivileges)
        return False
        
    def __iter__(self):
        return iter(self.reversemappinglist)
        
    def __delitem__(self, item):
        raise TypeError
        
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self.privileges[self.mapping[key]]
        elif isinstance(key, int):
            return self.privileges[key]
        else:
            raise KeyError
            
    def __setitem__(self, key, value):
        if isinstance(key, basestring):
            self.privileges[self.mapping[key]] = int(value)
        elif isinstance(key, int):
            self.privileges[key] = int(value)
        else:
            raise KeyError
    
    def getstring(self, protocolversion):
        """Get privilege string for given Wired protocol version
        
        protocolversion (float) - version of Wired protocol being used
        """
        if protocolversion == 1.0:
            return "\x1c".join(map(str,self.privileges[:20]))
        else:
            return "\x1c".join(map(str,self.privileges[:self.numprivileges]))
                
    def keys(self):
        """Get list of privilege types"""
        return self.reversemappinglist
        
    def update(self, privileges):
        """Update privileges
        
        privileges (list) - list of values of privileges, in the following 
            order: getuserinfo, broadcast, postnews, clearnews, download, 
            upload, uploadanywhere, createfolders, alterfiles, deletefiles,
            viewdropboxes, createaccounts, editaccounts, deleteaccounts,
            elevateprivileges, kickusers, banusers, cannotbekicked, 
            downloadspeed, uploadspeed, downloadlimit, uploadlimit, changetopic
        """
        self.privileges = map(int,privileges)
        if len(self.privileges) < self.numprivileges:
            self.privileges.extend([0]*(self.numprivileges-len(privileges)))
        elif len(self.privileges) > self.numprivileges:
            self.privileges = self.privileges[:self.numprivileges]
        return 0
        
class wireaccount:
    """Wired user or group account"""
    def __init__(self, name, privileges):
        self.name = '%s' % name
        self.privileges = privileges

    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
class wiregroupaccount(wireaccount):
    def __init__(self, name, privileges):
        """Initialize group account
        
        name (str) - name of group account
        privileges (wireprivileges) - privileges for account
        """
        wireaccount.__init__(self, name, privileges)

    def __unicode__(self):
        return "%s\x1c%s" % (self.name, self.privileges)
        
    def getstring(self, protocolversion):
        """Get group account string for given Wired protocol version
        
        protocolversion (float) - version of Wired protocol being used
        """
        return "%s\x1c%s" % (self.name, self.privileges.getstring(protocolversion))

class wireuseraccount(wireaccount):
    """Wired user account"""
    def __init__(self, name, password, groupname, privileges):
        """Initialize user account
        
        name (str) - name of user account
        privileges (wireprivileges) - privileges for account
        password (str) - password for account
        groupname (str) - name of group account with which the user is
            associated with (may be blank)
        """
        wireaccount.__init__(self, name, privileges)
        # If you plan to change the password, you must hash it with SHA-1
        # before sending the edit account request to the server
        self.password = password
        self.groupname = groupname

    def __unicode__(self):
        return "%s\x1c%s\x1c%s\x1c%s" % (self.name, self.password, self.groupname, self.privileges)
        
    def getstring(self, protocolversion):
        """Get user account string for given Wired protocol version
        
        protocolversion (float) - version of Wired protocol being used
        """
        return "%s\x1c%s\x1c%s\x1c%s" % (self.name, self.password, self.groupname, self.privileges.getstring(protocolversion))

    def setpassword(self, password):
        """Set a new password for this user account
        
        password (str) - the user's new password
        
        Notes: This function creates the SHA-1 password for the given password 
        and associates that hash with this account.  If you would like to set
        the hash directly, just call wireaccount.password = hash. Also, this 
        function doesn't change their password on the server, you need to call 
        wire.editaccount to do so.
        """
        self.password = sha.new(('%s' % password).encode('utf8','ignore')).hexdigest()
        return self.password
        
class wiretransfer:
    """Upload to or download from a Wired server"""
    def __init__(self, hostpath, serverpath):
        self.hostpath = hostpath
        self.serverpath = serverpath
        self.starttime, self.isdir = None, None
        self.fileposition, self.size, self.offset = 0, 0, 0
        # The position in the server queue for this file
        self.serverqueueposition = -1
        # Should we stop downloading this file
        self.stop = False
        # Last three times an error occured while uploading the file
        self.errortimes = [0,0,0]
    
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')

class wireupload(wiretransfer):
    """Upload to a Wired server"""
    def __init__(self, hostpath, serverpath):
        """Initialize potential upload
        
        hostpath (str) - local path to upload
        serverpath (str) - remote path at which to store uploaded files
        """
        assert os.path.exists(hostpath)
        wiretransfer.__init__(self, hostpath, serverpath)
        if os.path.isfile(hostpath):
            self.size = os.path.getsize(hostpath)
            fil = file(hostpath,'rb')
            self.checksum = sha.new(fil.read(1048576)).hexdigest()
            fil.close()
            self.isdir = False
        else:
            self.isdir = True
            self.size = len(os.listdir(hostpath))
        
    def __unicode__(self):
        return "Upload: %s -> %s" % (self.hostpath, self.serverpath)
            
class wiredownload(wiretransfer):
    """Download from a Wired server"""
    def __init__(self, serverpath, hostpath):
        """Initialize potential download
        
        serverpath (str, wirepath) - remote path to download
        hostpath (str) - local path at which to store downloaded files
        """
        serverfile = None
        if isinstance(serverpath, wirepath):
            serverfile = serverpath
            serverpath = serverfile.path
        wiretransfer.__init__(self, hostpath, serverpath)
        self.setserverfile(serverfile)
        
    def __unicode__(self):
        return "Download: %s -> %s" % (self.serverpath, self.hostpath)
        
    def setserverfile(self, serverfile):
        """Associate a serverfile with this download
        
        serverfile (wirepath) - wirepath associated with download
        """
        if isinstance(serverfile, wirepath):
            self.serverfile = serverfile
            self.size = serverfile.size
            self.isdir = bool(serverfile.type)
            return 0
        self.serverfile = None
        return 1
        
class wirechat:
    """Information about chats on a Wired server"""
    def __init__(self, chatid):
        """Initialize chat
        
        chatid (int) - the Wired ID for this chat
        """
        self.chatid = chatid
        self.users = []
        self.topicnick, self.topiclogin = None, None
        self.topicip, self.topictime = None, None
        self.topic = ''
        
    def __unicode__(self):
        return "Wire Chat ID: %s Topic: %s" % (self.chatid, self.topic)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
        
    def adduser(self, userid):
        """Add a user to this chat"""
        if userid not in self.users:
            self.users.append(userid)
            return 0
        return 1
        
    def removeuser(self, userid):
        """Remove a user from this chat"""
        if userid in self.users:
            self.users.remove(userid)
            return 0
        return 1
        
    def updatechattopic(self, nick, login, ip, time, topic):
        """Set the topic for this chat
        
        nick (str) - nick of user who set the topic
        login (str) - account of user who set the topic
        ip (str) - IP address of user who set the topic
        time (str) - string containing the time set, in Wired format
        topic (str) - topic for chat
        """
        self.topicnick = nick
        self.topiclogin = login
        self.topicip = ip
        self.topictime = parsewiredtime(time)
        self.topic = topic
        return 0
        
##  The wire class itself
    
class wire:
    """Controls connection to a server implementing the Wired protocol
    
    See http://www.zankasoftware.com/wired/rfc2.txt for description of 
    the Wired protocol.
    """
    nextid = 0
    
    def __init__(self,config='', **kwargs):
        """Initialize connection parameters
        
        See wire.conf for a list of keyword arguments you can provide.
        In addition to those listed in wire.conf, the following are also
        accepted:
        
        log (logging.Logger) = the python logger for the connection
        callbacks (dict) = contains callback functions, corresponding to codes
            returned from the wired server.  Keys should be 3 digit integers, 
            values should be functions. For example, if you have a key of 400 
            in callbacks, the corresponding function will be called whenever 
            the wired server returns that code.  These functions are passed 3
            arguments: the wire object, a list containing the arguments, and a
            flag denoting whether there was a problem with the response
            (0 for no problem, 1 for problem).
            
            There are also some string keys that are recognized for various 
            events that don't correspond with codes the server returns.  The 
            first argument is always this instance of wire. : 
            anymessage(wire, code, args, failure):
                Called in addition to any normal callback response.  Useful if 
                you are handling all the callbacks in a similar way but don't 
                want to define them all individually.
            controlconnectionclosed(wire):
                Called whenever the control connection to the server is closed.
                Useful for reconnecting.
            downloadfinished(wire, wiredownload, success):
                Called when a download has been finished. wiredownload is the 
                download that just finished, and success is whether the 
                transfer was successful or not (i.e. no socket errors occured).
            downloadqueueprocessed(wire):
                Called when the library has finished processing the download
                queue.  This doesn't mean there is nothing left, it just means
                that the function call to _get has finished.  This will always
                be called if the download queue has been modified.
            gotunrecognizedmessage(wire, servermessage):
                Called when the server sends a message that this module
                doesn't recognize. message is the message the server sent.
            ping(wire):
                Called after pinging the server (every 10 minutes).  Useful for
                doing something on a regular basis.
            uploadfinished(wire, wireupload, success):
                Same as downloadfinished, but for uploads.
            uploadqueueprocessed(wire):
                Same as downloadqueueprocessed, but for uploads.
                
        Note: Unicode can be used for most string arguments
        """
        self.version = __version__
        self.buffersize = 8192
        self.timeout = 15
        self.host = '127.0.0.1'
        self.port = 2000
        self.nick = 'Default User'
        self.login = 'guest'
        self.password = ''
        self.passwordhash = ''
        self.appname = ''
        self.config = os.path.abspath(config)
        self.icon = 0
        self.callbacks = {}
        self.log = None
        self.logfile = ''
        self.loglevel = 'DEBUG'
        self.buffer = ''
        self.defaulthostdir = ''
        # defaultserverdir should always end with a slash
        self.defaultserverdir = '/'
        self.queuefile = ''
        self.clientversionstring = ''
        self.status = ''
        self.imagefile = None
        self.image = ''
        self.id = self.__class__.nextid
        self.__class__.nextid += 1
        self.usepasswordhash = False
        self.errortimeout = 120
        self.downloadcheckbuffer = 1024
        self.maxsimultaneousdownloads = 1
        self.maxsimultaneousuploads = 1
        # This library uses threads, and this lock is very important
        # Always acquire the lock using self.acquirelock() before making any 
        # changes to the internal data structures.  Note that you should
        # release the lock using self.releaselock after you have finished
        # modifying the datastructures (failure to do so will probably result 
        # in the program freezing)
        self.lock = thread.allocate_lock()
        self.socket, self.tlssocket = None, None
        curdir = os.getcwd()
        os.chdir(os.path.dirname(self.config))
        self.defaulthostdir = os.getcwd()
        self.loadconfig(self.config, **kwargs)
        if self.queuefile == '':
            self.queuefile = os.path.abspath('%s.wq' % self.host)
        os.chdir(curdir)
        if self.log is None:
            self.log = logging.getLogger('wire.default.%s' % self.id)
            self.defaultloghandler = logging.StreamHandler(sys.stdout)
            self.defaultlogformatter = logging.Formatter('%(levelname)s: %(message)s')
            self.defaultloghandler.setFormatter(self.defaultlogformatter)
            self.log.addHandler(self.defaultloghandler)
            if self.logfile != '':
                try:
                    self.defaultlogfilehandler = logging.FileHandler(self.logfile)
                    self.defaultlogfileformatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
                    self.defaultlogfilehandler.setFormatter(self.defaultlogfileformatter)
                    self.log.addHandler(self.defaultlogfilehandler)
                except:
                    pass
            self.log.setLevel(logging.__dict__[self.loglevel])
        if self.clientversionstring == '':
            self.clientversionstring = self.getclientversionstring()
        if not self.usepasswordhash and self.password != '':
            self.passwordhash = sha.new(self.password.encode('utf8','ignore')).hexdigest()
        self._resetfilestructures()
        
    ### Functions that should not be called by the user
    
    def __unicode__(self):
        return "Wired client, connected to %s:%s as %s" % (self.host, self.port, self.login)
        
    def __str__(self):
        return (unicode(self)).encode('ascii','ignore')
          
    def _get(self):
        """Download next file in download queue"""
        # This function should only be called while in posession of the lock
        failure = False
        while True:
            if self.tlssocket == None or self.tlssocket.closed:
                self.log.debug('_get called, but control connection has been closed')
                failure = True
                break
            if self.downloadqueue == []:
                self.log.debug('_get called with nothing in downloadqueue')
                break
            numcurrentdownloads = len(self.currentdownloads)
            if  numcurrentdownloads >= self.maxsimultaneousdownloads:
                self.log.debug('_get called, but currently downloading %s files' % numcurrentdownloads)
                break
            # If you are trying to download a directory with many subdirectories
            # and files, and all of the information is already in the file and 
            # filelist caches, _get can take a very long time.  Since this 
            # library is threaded, it's not a good idea to spend a large amount
            # of time without yielding the lock. Releasing and reacquiring the
            # lock should keep programs who use this library responsive
            self.releaselock(True)
            self.acquirelock()
            # The download queue works partly like a stack and partly like a queue
            # It's like a queue because paths the user puts in it are downloaded
            # in a first in first out basis.  It's like a stack because it does 
            # a depth first traversal of the subdirectories and files of that
            # path, which are processed on a last in first out basis
            download = self.downloadqueue[-1]
            if not isinstance(download, wiredownload):
                if callable(download):
                    download()
                if isinstance(download,(tuple,list)) and callable(download[0]):
                    download[0](*download[1], **download[2])
                self.downloadqueue.pop()
                continue
            serverpath, hostpath = download.serverpath, download.hostpath
            self.log.debug('_get called with %s items in queue, next item download %s' % (len(self.downloadqueue),unicode(download)))
            if serverpath not in self.files:
                # This path should only be taken for the path actually submitted
                # by the user.  Files and subdirectories below that path should
                # already have this information by the time they get to this step
                self.getfileinfo(serverpath)
                break
            # Set the serverfile for the download, so we can access the 
            # size and checksum information, if available
            download.setserverfile(self.files[serverpath])
            if self.files[serverpath].type != 0:
                # Path taken for directories
                if serverpath not in self.filelists:
                    self.getfilelist(serverpath)
                    break
                else:
                    if not os.path.exists(hostpath):
                        # If the directory we are downloading doesn't exist
                        # on the local filesystem, create it
                        os.mkdir(hostpath)
                    elif not os.path.isdir(hostpath):
                        self.log.error('Can\'t download directory , destination is file: %s' % unicode(download))
                        self.downloadqueue.pop()
                        continue
                # Remove the directory from the queue
                self.downloadqueue.pop()
                fils = [f for f in self.files.keys() if os.path.dirname(f) == serverpath and f != '/']
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
                        self.log.error('Can\'t download file, destination is directory: %s' % unicode(download))
                    elif self.files[serverpath].size != os.path.getsize(hostpath):
                        self.log.error('Download already marked complete, but file sizes do not match: Host: %s (%s) Server: %s (%s)' % (hostpath, os.path.getsize(hostpath), serverpath, self.files[serverpath].size))
                    else:
                        self.log.debug('Download already complete: %s' % unicode(download))
                    self.downloadqueue.pop()
                    continue
                hostpathwpf = hostpath + '.wpf'
                if(os.path.exists(hostpathwpf)):
                    if not os.path.isfile(hostpathwpf):
                        self.log.error('Can\'t download file, destination is directory: %s' % unicode(download))
                        self.downloadqueue.pop()
                        continue
                    elif self.files[serverpath].size <= os.path.getsize(hostpathwpf):
                        if self.files[serverpath].size < os.path.getsize(hostpathwpf):
                            self.log.error('File on server is smaller than partially downloaded file: Host: %s (%s) Server: %s (%s)' % (hostpathwpf, os.path.getsize(hostpathwpf), serverpath, self.files[serverpath].size))
                        else:
                            self.log.warning('Download already complete, but still marked as partial file: $s' % unicode(download))
                        self.downloadqueue.pop()
                        continue
                    elif self.files[serverpath].checksum == None:
                        # If the file exists locally and we don't have the
                        # remote checksum, we need to get it to see if it matches
                        self.getfileinfo(serverpath)
                        break
                    size = os.path.getsize(hostpathwpf)
                    fil = file(hostpathwpf,'rb')
                    checksum = sha.new(fil.read(1048576)).hexdigest()
                    fil.close()
                    if self.files[serverpath].checksum == checksum:
                        # If the checksums match, we don't have to download the 
                        # entire file again
                        if size > self.downloadcheckbuffer:
                            download.offset = size -  self.downloadcheckbuffer
                    else:
                        # If the checksums don't match, we'll try to rename the
                        # old file, or remove it if it looks like we already have
                        # a second copy of it
                        try:
                            self.log.info("Checksums don't match, attempting to rename local file: %s" % unicode(download))
                            fil = file(hostpathwpf,'rb')
                            checksum2 = checksum
                            if size > 1048576:
                                fil.seek(-1048576,2)
                                checksum2 = sha.new(fil.read()).hexdigest()
                            newname = '%s.%s.wfd' % (hostpath, checksum2)
                            fil.close()
                            os.rename(hostpathwpf, newname)
                        except OSError:
                            try:
                                if os.path.exists(newname) and os.path.isfile(newname) and os.path.getsize(hostpathwpf) == os.path.getsize(newname):
                                    self.log.info("Rename failed, looks like the files match, attempting to remove local file: %s" % unicode(download))
                                    os.remove(hostpathwpf)
                                else:
                                    self.log.error("Skipping download, rename failed and looks like the files don't match: %s" % unicode(download))
                                    self.downloadqueue.pop()
                                    continue
                            except OSError:
                                self.log.error("Skipping download, checksums don't match and local file couldn't be renamed or removed: %s" % unicode(download))
                                self.downloadqueue.pop()
                                continue
                self.log.debug('Sending get message for transfer: %s' % unicode(download))
                self.requested['downloads'].append(serverpath)
                self.currentdownloads[serverpath] = self.downloadqueue.pop()
                if serverpath in self.files:
                    self.currentdownloads[serverpath].setserverfile(self.files[serverpath])
                if self._send("GET %s\x1c%s\04" % (serverpath, download.offset)):
                    self.requested['downloads'].pop()
                    del self.currentdownloads[serverpath]
                    failure = True
                    break
                continue
        if 'downloadqueueprocessed' in self.callbacks:
            self.callbacks['downloadqueueprocessed'](self)
        return int(failure)
                      
    def _listen(self):
        """Listen for responses from server"""
        acquired = self.acquirelock()
        self.listenid = thread.get_ident()
        self.socket.settimeout(None)
        data = u''
        responses = {200:self._gotserverinfo, 201:self._gotloginsucceeded, 
            202:self._gotpong, 203:self._gotserverbanner, 
            300:self._gotchat, 301:self._gotactionchat,
            302:self._gotclientjoin, 303:self._gotclientleave, 
            304:self._gotstatuschange, 305:self._gotprivatemessage, 
            306:self._gotclientkicked, 307:self._gotclientbanned, 
            308:self._gotuserinfo, 309:self._gotbroadcast,
            310:self._gotuserlist, 311:self._gotuserlistdone,
            320:self._gotnews, 321:self._gotnewsdone, 322:self._gotnewsposted,
            330:self._gotprivatechatcreated, 331:self._gotprivatechatinvite,
            332:self._gotprivatechatdeclined, 400:self._gottransferready,
            340:self._gotclientimagechanged, 341:self._gotchattopic,
            401:self._gottransferqueued, 402:self._gotfileinfo,
            410:self._gotfilelist, 411:self._gotfilelistdone,
            420:self._gotsearchlist, 421:self._gotsearchlistdone,
            500:self._gotcommandfailed, 501:self._gotcommandnotrecognized,
            502:self._gotcommandnotimplemented, 503:self._gotsyntaxerror,
            510:self._gotloginfailed, 511:self._gotbanned,
            512:self._gotclientnotfound, 513:self._gotaccountnotfound, 
            514:self._gotaccountexists, 515:self._gotcannotbedisconnected,
            516:self._gotpermissiondenied, 520:self._gotfilenotfound,
            521:self._gotfileexists, 522:self._gotchecksummismatch,
            600:self._gotaccountspec, 601:self._gotgroupspec, 602:self._gotprivileges, 
            610:self._gotaccountlist, 611:self._gotaccountlistdone,
            620:self._gotgrouplist, 621:self._gotgrouplistdone}
        self.log.debug('Starting Listening Loop')
        try:
            while self.tlssocket != None and not self.tlssocket.closed:
                acquired = self.releaselock(acquired)
                # Get the data from the socket, and convert it to unicode
                data += self.tlssocket.recv(self.buffersize).decode('utf8')
                acquired = self.acquirelock()
                failure = None
                nextcommandend = data.find('\04')
                if nextcommandend == -1:
                    continue
                nextcommand = data[:nextcommandend]
                commandnum = int(nextcommand[:3])
                # Split the commands arguments by the ascii field separator
                args = nextcommand[4:].split("\x1C")
                data = data[nextcommandend+1:]
                self.log.debug('Server response: %s' % nextcommand)
                if commandnum in responses:
                    failure = responses[commandnum](args)
                else:
                    self._gotunrecognizedmessage(nextcommand)
                    if 'gotunrecognizedmessage' in self.callbacks:
                        self.callbacks['gotunrecognizedmessage'](self, nextcommand)
                if commandnum in self.callbacks:
                    self.callbacks[commandnum](self, args, failure)
                if 'anymessage' in self.callbacks:
                    self.callbacks['anymessage'](self, commandnum, args, failure)
        except (socket.error, TLSError, ValueError):
            if self.connected:
                self.log.exception("Control connection closed")
        except:
            self.log.exception("Serious error in listen thread")
        if self.lockid == self.listenid:
            self.releaselock(acquired)
        self.listenid = 0
        self.disconnect()
        if 'controlconnectionclosed' in self.callbacks:
            self.callbacks['controlconnectionclosed'](self)
            
    def _pingserver(self):
        """Ping the server on a regular basis"""
        # The only purpose of this is to keep the connection alive
        failure = False
        acquired = False
        try:
            while not failure and self.tlssocket != None and not self.tlssocket.closed:
                time.sleep(600)
                acquired = self.acquirelock()
                if not self.tlssocket.closed:
                    self.log.debug('Pinging server')
                    self.requested['pong'] = True
                    failure = self._send("PING\04")
                if 'ping' in self.callbacks:
                    self.callbacks['ping'](self)
                acquired = self.releaselock(acquired)
                if failure:
                    break
        except:
            self.log.exception("Serious error in _pingserver thread")
        self.releaselock(acquired)
    
    def _put(self):
        """Upload next file in upload queue"""
        # Most of the comments in _get are also applicable here
        failure = False
        while True:
            if self.tlssocket == None or self.tlssocket.closed:
                self.log.debug('_put called, but control connection has been closed')
                failure = True
                break
            if self.uploadqueue == []:
                self.log.debug('_put called with nothing in uploadqueue')
                break
            numcurrentuploads = len(self.currentuploads)
            if  numcurrentuploads >= self.maxsimultaneousuploads:
                self.log.debug('_put called, but currently uploading %s files' % numcurrentuploads)
                break
            self.releaselock(True)
            self.acquirelock()
            upload = self.uploadqueue[-1]
            if not isinstance(upload, wireupload):
                if callable(upload):
                    upload()
                if isinstance(upload,(tuple,list)) and callable(upload[0]):
                    upload[0](*upload[1], **upload[2])
                self.uploadqueue.pop()
                continue
            hostpath, serverpath = upload.hostpath, upload.serverpath
            serverdir = os.path.dirname(serverpath)
            self.log.debug('_put called, queue length %s, next item upload %s' % (len(self.uploadqueue), unicode(upload)))
            if serverdir not in self.filelists:
                # Since you may be uploading a file or directory that doesn't  
                # yet exist on the server, you can't call getfileinfo.
                # However, the parent directory of the file should exist, so 
                # check that and see if the path we are uploading already exists
                if serverdir not in self.requested['filelists']:
                    self.getfilelist(serverdir)
                break
            elif serverdir not in self.files:
                # Need to check to see if serverdir is an upload directory
                if serverdir not in self.requested['fileinfo']:
                    self.getfileinfo(serverdir)
                break
            elif os.path.isdir(hostpath):
                if serverpath not in self.files:
                    if not self.privileges['createfolders'] :
                        self.log.warning("You don't have the privileges to create folders")
                        self.uploadqueue.pop()
                        continue
                    # Unfortunately, we can't check if the creation is succesful
                    self.createfolder(serverpath)
                elif self.files[serverpath].type == 0:
                    self.log.error('Can\'t upload directory, destination is file: %s' % unicode(upload))
                    self.uploadqueue.pop()
                    continue
                fils = os.listdir(hostpath)
                fils.sort()
                fils.reverse()
                self.uploadqueue.pop()
                self.uploadqueue.append([self.getfilelist,[serverpath],{}])
                for fil in fils:
                    self.uploadqueue.append(wireupload(os.path.join(hostpath,fil), "%s/%s" % (serverpath, fil)))
                continue
            elif os.path.isfile(hostpath):
                if self.files[serverdir].type == 1 and not self.privileges['uploadanywhere']:
                    self.log.error("You don't have the privileges to upload anywhere, try uploading to an Uploads folder.")
                    self.uploadqueue.pop()
                    continue
                if serverpath in self.files:
                    if self.files[serverpath].type != 0:
                        self.log.error('Can\'t upload file, destination is directory: %s' % unicode(upload))
                    elif self.files[serverpath].size > upload.size:
                        self.log.warning('File on server larger than file on host and already marked complete: %s' % unicode(upload))
                    elif self.files[serverpath].size == upload.size:
                        self.log.debug('Upload already complete: %s' % unicode(upload))
                    else:
                        self.log.warning('File on server smaller than file on host, but already marked complete: %s' % unicode(upload))
                    self.uploadqueue.pop()
                    continue
                serverpathwt = serverpath + '.WiredTransfer'
                if serverpathwt in self.files:
                    if self.files[serverpathwt].size >= upload.size:
                        if self.files[serverpathwt].size == upload.size:
                            self.log.warning('Upload already complete, but still marked as a partial file: %s' % unicode(upload))
                        else:
                            self.log.error('Partial file on server larger than file to upload: %s' % unicode(upload))
                        self.uploadqueue.pop()
                        continue
                    elif self.filelists[serverdir]['freeoctets'] < upload.size - self.files[serverpathwt].size:
                        self.log.error('Not enough space to upload: %s' % unicode(upload))
                        self.uploadqueue.pop()
                        continue
                elif self.filelists[serverdir]['freeoctets'] < upload.size:
                    self.log.error('Not enough space to upload: %s' % unicode(upload))
                    self.uploadqueue.pop()
                    continue
                self.log.debug('Sending put message for transfer: %s' % unicode(upload))
                self.requested['uploads'].append(serverpath)
                self.currentuploads[serverpath] = self.uploadqueue.pop()
                if self._send("PUT %s\x1c%s\x1c%s\04" % (serverpath, upload.size, upload.checksum)):
                    self.requested['uploads'].pop()
                    del self.currentuploads[serverpath]
                    failure = True
                    break
                continue
            else:
                # Must be something special if it's not a file or directory
                # Or maybe it doesn't exist anymore
                # In case case, better off not uploading it
                self.uploadqueue.pop()
                continue
        if 'uploadqueueprocessed' in self.callbacks:
            self.callbacks['uploadqueueprocessed'](self)
        return int(failure)
        
    def _receivefile(self, transfer, offset, hash):
        """Connect to transfer port and download file
        
        transfer (wiredownload) - the wiredownload to receive
        offset (int) - the offset at which to begin the file writing (should be
            at the end of the file)
        hash (str) - the hash corresponding to this transfer request
        """
        self.log.debug('_receivefile called with (%s,%s,%s)' % (transfer, offset, hash))
        sock, tlssocket = None, None
        offset = int(offset)
        success, attemptagain = False, False
        hostpath = transfer.hostpath
        hostpathwpf = hostpath + '.wpf'
        serverpath = transfer.serverpath
        filsize = transfer.serverfile.size
        buffersize = self.buffersize
        checkbuffer = None
        checkdata = ""
        needtocheck = False
        fil = None
        if offset != 0:
            needtocheck = True
        self.log.debug('Connecting to transfer socket')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host,self.port+1))
            tlssocket = TLSConnection(sock)
            tlssocket.handshakeClientCert()
            self.log.debug('Sending transfer request for download: %s' % unicode(transfer))
            # Don't need to utf encode this because hash is always hexadecimal
            tlssocket.send("TRANSFER %s\04" % hash)
            sock.settimeout(None)
            self.log.debug('Opening file for download: %s' % unicode(transfer))
            if needtocheck:
                fil = file(hostpathwpf,'rb')
                fil.seek(offset)
                checkbuffer = fil.read()
                fil.close()
            fil = file(hostpathwpf,'a+b')
            self.log.info('Starting download of %s at offset %s' % (unicode(transfer), offset))
            transfer.starttime = time.time()
            while fil.tell() < filsize:
                if transfer.stop or tlssocket.closed:
                    if transfer.stop != 1:
                        attemptagain = True
                    transfer.stop = False
                    break
                data = tlssocket.recv(buffersize)
                if needtocheck:
                    checkdata += data
                    if len(checkdata) < len(checkbuffer):
                        continue
                    if checkdata[:len(checkbuffer)] != checkbuffer:
                        self.log.error('Host file is not a partial file of server file, will attempt to redownload: %s' % unicode(transfer))
                        if fil.tell() > 1048576:
                            fil.seek(-1048576,2)
                        else:
                            fil.seek(0)
                        newname = '%s.%s.wfd' % (hostpath, sha.new(fil.read()).hexdigest())
                        fil.close()
                        os.rename(hostpathwpf, newname)
                        self.currentdownloads[serverpath].offset = 0
                        raise TLSError
                    data = checkdata[len(checkbuffer):]
                    checkdata = None
                    needtocheck = False
                fil.write(data)
                transfer.fileposition = fil.tell()
            else:
                fil.close()
                os.rename(hostpathwpf, hostpath)
                success = True
                self.log.info('Finished downloading: %s' % unicode(transfer))
        except (socket.error, TLSError, ValueError):
            self.log.exception("Download connection closed")
            attemptagain = True
        except:
            self.log.exception("Serious error in _receivefile thread")
        tlssocket = None
        sock = None
        if isinstance(fil, file):
            fil.close()
        acquired = self.acquirelock()
        try:
            if serverpath in self.currentdownloads:
                if attemptagain:
                    curtime = time.time()
                    errortime = curtime - transfer.errortimes.pop(0)
                    transfer.errortimes.append(curtime)
                    transfer.starttime = None
                    if errortime < self.errortimeout:
                        self.log.info("Many recurrent errors downloading in a short period, skipping download: %s" % unicode(transfer))
                    else:
                        self.downloadqueue.append(self.currentdownloads[serverpath])
                del self.currentdownloads[serverpath]
            if 'downloadfinished' in self.callbacks:
                self.callbacks['downloadfinished'](self, transfer, success)
            self._get()
        finally:
            self.releaselock(acquired)
        return 0
        
    def _removeuser(self, userid):
        """Remove user, add to list of dead users"""
        if isinstance(userid,int) and userid in self.users:
            self.deadusers[userid] = self.users[userid]
            del self.users[userid]
        
    def _resetfilestructures(self):
        """Reset various internal file structures"""
        self.chats, self.users, self.files, self.filelists = {}, {}, {}, {}
        self.accounts, self.groups, self.privatechatinvites = {}, {}, {}
        self.searches, self.currentdownloads, self.currentuploads = {}, {}, {}
        self.news, self.uploadqueue, self.downloadqueue = [], [], []
        self.connected = False
        self.sockstring = ''
        self.serverappversion, self.serverprotocolversion = None, None
        self.servername, self.serverdescription = None, None
        self.serverstarttime, self.myuserid = None, None
        self.lockid, self.listenid = 0, 0
        self.serverfilescount, self.serverfilessize = 0, 0
        self.deadusers = {}
        self.privileges = wireprivileges()
        self.requested = {'accountlist':False, 'grouplist':False, 'pong':False,
            'readuser':[], 'readgroup':[], 'news':False, 'filelists':[],
            'searchlists':[], 'fileinfo':[], 'privatechat':0, 'userinfo':[],
            'userlist':[], 'uploads':[], 'downloads':[], 'login':False,
            'connect':False, 'banner':False}
                
    def _restartdownloadqueueifpathmatches(self, path, requested = False):
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
        
    def _restartuploadqueueifpathmatches(self, path, requested = False):
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
        
    def _send(self, data):
        """Send a command to the Wired server
        
        data (str) - data to send to the Wired server
        """
        self.log.debug('Sending command to server: %s' % data)
        data = data.encode('utf8')
        try:
            self.tlssocket.send(data)
        except (socket.error, TLSError, AttributeError, ValueError):
            self.log.exception("Error sending message to server")
            return 1
        return 0
            
    def _sendfile(self, transfer, offset, hash):
        """Connect to transfer port and upload file
        
        transfer (wireupload) - the wireupload to transfer
        offset (int) - the offset at which to start the transfer
        hash (str) - the hash corresponding to this transfer request
        """
        # See comments in receive file, as these operate similarly
        sock, tlssocket = None, None
        success, attemptagain = False, False
        hostpath, serverpath = transfer.hostpath, transfer.serverpath
        buffersize = self.buffersize
        transfer.offset = int(offset)
        filsize = os.path.getsize(hostpath)
        self.log.debug('Opening file for upload: %s' % unicode(transfer))
        fil = file(hostpath,'rb')
        fil.seek(transfer.offset)
        self.log.debug('Connecting to transfer socket')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host,self.port+1))
            tlssocket = TLSConnection(sock)
            tlssocket.handshakeClientCert()
            self.log.debug('Sending transfer request for upload: %s' % unicode(transfer))
            tlssocket.send("TRANSFER %s\04" % hash)
            sock.settimeout(None)
            self.log.info('Starting upload of %s at offset %s' % (unicode(transfer), offset))
            transfer.starttime = time.time()
            while fil.tell() < filsize:
                if transfer.stop or tlssocket.closed:
                    if transfer.stop != 1:
                        attemptagain = True
                    transfer.stop = False
                    break
                tlssocket.send(fil.read(self.buffersize))
                transfer.fileposition = fil.tell()
            else:
                if not tlssocket.closed:
                    tlssocket.close()
                success = True
                self.log.info('Finished uploading: %s' % unicode(transfer))
        except (socket.error, TLSError, ValueError):
            self.log.exception("Upload connection closed")
            attemptagain = True
        except:
            self.log.exception("Serious error in _sendfile thread")
        tlssocket = None
        sock = None
        fil.close()
        acquired = self.acquirelock()
        try:
            if serverpath in self.currentuploads:
                if attemptagain:
                    curtime = time.time()
                    errortime = curtime - transfer.errortimes.pop(0)
                    transfer.errortimes.append(curtime)
                    transfer.starttime = None
                    if errortime < self.errortimeout:
                        self.log.info("Many recurrent errors uploading in a short period, skipping upload: %s" % unicode(transfer))
                    else:
                        self.uploadqueue.append(self.currentuploads[serverpath])
                del self.currentuploads[serverpath]
            if 'uploadfinished' in self.callbacks:
                self.callbacks['uploadfinished'](self, transfer, success)
            self._put()
        finally:
            self.releaselock(acquired)
        return 0
        
    ### Utility Functions
    
    def acquirelock(self):
        """Acquire lock if lock is not currently possessed by the current thread"""
        lockid = thread.get_ident()
        if self.lockid != lockid:
            self.lock.acquire()
            self.lockid = lockid
            return True
        return False
        
    def validchat(self, chatid):
        """Return True if chatid in chats, otherwise return False"""
        if chatid in self.chats:
            return True
        return False
    
    def clearuploadqueue(self):
        """Clear the upload queue"""
        self.log.debug('Clearing the upload queue')
        self.uploadqueue = []
        return 0
        
    def cleardownloadqueue(self):
        """Clear the download queue"""
        self.log.debug('Clearing the download queue')
        self.downloadqueue = []
        return 0
        
    def forgetpath(self, path, forget=['files','filelists']):
        """Forget path and all subpaths
        
        path (str) - path to forget"""
        # If any of the paths in the upload or download queue are subpaths of
        # this path, you may run into problems later
        self.log.debug('Forgetting all paths starting with %s' % path)
        if 'files' in forget:
            for fil in [f for f in self.files if f.startswith(path)]:
                del self.files[fil]
        if 'filelists' in forget:
            for fil in [f for f in self.filelists if f.startswith(path)]:
                del self.filelists[fil]
        return 0
        
    def getclientversionstring(self):
        """Return client version string"""
        osname = ''
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
        return "%s (%s) %s" % (self.appname, osname, libversion)
        
    def loadconfig(self, config, **kwargs):
        """Get configuration from file or keyword arguments
        
        config (str) - path to configuration file
        **kwargs - other keyword arguments that override the defaults and the
            values in config"""
        if config != '':
            rcp = RawConfigParser()
            rcp.read(config)
            if rcp.has_section('wire'):
                for key, value in [(key, value) for (key, value) in rcp.items('wire') if key not in kwargs]:
                    kwargs[key] = value
        for key, value in [(key, value) for (key, value) in kwargs.items() if key in dir(self)]:
            if isinstance(getattr(self, key), int):
                setattr(self, key, int(value))
            else:
                if key in 'imagefile logfile defaulthostdir queuefile'.split():
                    setattr(self, key, os.path.abspath(value))
                else:
                    setattr(self, key, value)
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
        
    def processdownloadqueue(self):
        """Process the download queue

        Since processing the queue can take a long time if all of the information
        is available, the main thread can spawn a new thread for this function,
        which takes care of the locking (after it is wrapped by a decorator).
        """
        self._get()
        
    def processuploadqueue(self):
        """Process the upload queue (see docstring for processdownloadqueue)"""
        self._put()
        
    def releaselock(self, release = True):
        """Release the lock if the argument is True"""
        if release:
            try:
                assert self.lockid == thread.get_ident()
            finally:
                self.lockid = 0
                self.lock.release()
                return False
        return False
        
    def restorequeues(self, filename = '', starttransfers = False):
        """Restore the previously saved upload and download queues
        
        filename (str) - the name of the file where the queues and caches are 
            stored
        starttrasnfers (bool) - whether to immediately start the transfers 
            after restoring the queues
            
        Note: This requires overwriting the current upload and download
        queues
        """
        if filename == '':
            filename = self.queuefile
        try:
            queuefile = file(filename, 'rb')
            frompickle = cPickle.load(queuefile)
            queuefile.close()
            for name in ['uploadqueue','downloadqueue']:
                queue = getattr(self, name)
                for item in frompickle[name]:
                    if isinstance(item, wiretransfer):
                        queue.append(item)
                    elif isinstance(item, basestring):
                        if hasattr(self, item):
                            queue.append(getattr(self, item))
                        elif item in self.callbacks:
                            queue.append(self.callbacks[item])
                    elif isinstance(item, (list, tuple)) and isinstance(item[0], basestring):
                        if hasattr(self, item[0]):
                            queue.append([getattr(self, item[0])] + item[1:])
                        elif item[0] in self.callbacks:
                            queue.append([self.callbacks[item[0]]] + item[1:])
            self.log.info('Queues restored')
            if starttransfers:
                if len(self.downloadqueue) > 0:
                    thread.start_new_thread(self.processdownloadqueue,())
                if len(self.uploadqueue) > 0:
                    thread.start_new_thread(self.processuploadqueue,())
        except (OSError, IOError, KeyError):
            self.log.exception("Couldn't restore queues")
            self.downloadqueue = []
            self.uploadqueue = []
        return 0
        
    def savequeues(self, filename = ''):
        """Save the upload and download queues so they can be restored later
        
        filename (str) - the name of the file where the queues and caches 
            should be stored
        """
        if filename == '':
            filename = self.queuefile
        topickle = {}
        for name in ['uploadqueue','downloadqueue']:
            topickle[name] = []
            for item in getattr(self, name):
                if isinstance(item, wiretransfer):
                    topickle[name].append(item)
                elif callable(item):
                    topickle[name].append(item.__name__)
                elif isinstance(item, (list, tuple)) and callable(item[0]):
                    topickle[name].append([item[0].__name__] + item[1:])
        try:
            queuefile = file(filename, 'wb')
            cPickle.dump(topickle, queuefile)
            queuefile.close()
            self.log.info('Queues saved')
        except (OSError, IOError, KeyError):
            self.log.exception("Couldn't save queues")
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
    
    def changeicon(self, icon, imagefile = None):
        """Change icon
        
        icon (int) - icon number to which to change
        image (file, str) - optional filelike object or file location 
            containing the client's custom image
        """
        failure = True
        self.log.info('Changing icon to %s' % icon)
        self.icon = icon
        if self.serverprotocolversion >= 1.1:
            image = ""
            if isinstance(imagefile, basestring) and os.path.exists(imagefile):
                self.imagefile = imagefile
                imagefile =  file(imagefile,'rb')
                image = imagefile.read().encode('base64')
                imagefile.close()
            elif isinstance(imagefile, file):
                image = imagefile.read().encode('base64')
            self.image = image
            failure = self._send("ICON %s\x1c%s\04" % (icon, image))            
        else:
            failure = self._send("ICON %s\04" % icon)
        return int(failure)

    def changenick(self, nick):
        """Change nick
        
        nick (str) - nick to which to change
        """
        failure = True
        self.nick = nick
        self.log.info('Changing nick to %s' % nick)
        failure = self._send("NICK %s\04" % nick)
        return int(failure)
        
    def changestatus(self, status):
        """Change the status string for this connection
        
        status (str) - the new status
        """
        failure = True
        if self.serverprotocolversion >= 1.1:
            self.log.info('Changing current status to: %s' % status)
            self.status = status
            failure = self._send("STATUS %s\04" % status)
        else:
            self.log.warning("Server doesn't support the STATUS command")
        return int(failure)
        
    def connect(self):
        """Connect to the Wired Server"""
        if self.connected:
            self.log.warning('You are already connected')
            return 1
        self._resetfilestructures()
        failure = True
        if not self.requested['connect']:
            try:
                self.log.info('Attempting to connect to server')
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.timeout)
                self.socket.connect((self.host,self.port))
                self.log.debug('Socket connection established, attempting to establish TLS connection')
                self.tlssocket = TLSConnection(self.socket)
                self.tlssocket.handshakeClientCert()
                self.log.debug('TLS connection established, starting listen thread')
                thread.start_new_thread(self._listen,())
                thread.start_new_thread(self._pingserver,())
                self.requested['connect'] = True
                self.connected = True
                self.sockstring = '%s-%s' % ('%s-%s' % self.socket.getsockname(),'%s-%s' % self.socket.getpeername())
                failure = self._send("HELLO\04")
            except (socket.error, TLSError, ValueError, AssertionError):
                self.log.exception("Couldn't connect or login to server")
                self.tlssocket =  None
                self.socket = None
        else:
            self.log.warning("You already have an outstanding connection request")
        if failure:
            self.requested['connect'] = False
            self.connected = False
        return int(failure)
        
    def disconnect(self):
        """Disconnect from the Wired Server"""
        self.log.info('Disconnecting from server')
        self.connected = False
        if self.tlssocket != None:
            try:
                self.tlssocket.close()
            except:
                pass
            self.tlssocket = None
        self.socket = None
        for serverpath, download in self.currentdownloads.items():
            if download.serverqueueposition == 0:
                self.downloadqueue.append(download)
                del self.currentdownloads[serverpath]
        for serverpath, upload in self.currentuploads.items():
            if upload.serverqueueposition == 0:
                self.uploadqueue.append(upload)
                del self.currentuploads[serverpath]
        return 0
        
    def getbanner(self):
        """Get the server's banner"""
        failure = True
        if self.requested['banner']:
            self.log.warning("You already have an outstanding request for the banner")
        elif self.serverprotocolversion >= 1.1:
            self.log.info('Requesting server banner')
            self.requested['banner'] = True
            failure = self._send("BANNER\04")
        else:
            self.log.warning("Server doesn't support the BANNER command")
        return int(failure)
        
    def getprivileges(self):
        """Get privileges for this connection"""
        failure = True
        self.log.info('Requesting privileges')
        failure = self._send("PRIVILEGES\04")
        return int(failure)
        
    ## Account Functions
    
    def createaccount(self, name, password = '', group = '', privileges = None):
        """Create a new user account
        
        name (str) - name of account
        password (str) - password for account
        group (str) - group in which the account should be
        privileges (wireprivileges) - privileges for account
        """
        if privileges is None:
            privileges = wireprivileges()
        if name in self.accounts:
            self.log.error('The user account you provided (%s) already exists' % name)
            return 1
        failure = True
        if self.privileges['createaccounts']:
            self.log.info('Creating new user account: %s' % name)
            failure = self._send("CREATEUSER %s\x1c%s\x1c%s\x1c%s\04" % (name, password, group, privileges.getstring(self.serverprotocolversion)))
        else:
            self.log.warning('You don\'t have the privileges to create an account')
        return int(failure)
        
    def creategroup(self, name, privileges = None):
        """Create a new group
        
        name (str) - name of group
        privileges (wireprivileges) - privileges for group
        """
        if privileges is None:
            privileges = wireprivileges()
        if name in self.groups:
            self.log.error('The group account you provided (%s) already exists' % name)
            return 1
        failure = True
        if self.privileges['createaccounts']:
            self.log.info('Creating new group account: %s' % name)
            failure = self._send("CREATEGROUP %s\x1c%s\04" % (name, privileges.getstring(self.serverprotocolversion)))
        else:
            self.log.warning('You don\'t have the privileges to create a group account')
        return int(failure)
        
    def deleteaccount(self, name):
        """Delete a user account
        
        name (str) - name of account to delete
        """
        if name not in self.accounts:
            self.log.error("You did not provide a valid user account, or you haven't run getaccounts")
            return 1
        failure = True
        if self.privileges['deleteaccounts']:
            self.log.info('Deleting user account: %s' % name)
            failure = self._send("DELETEUSER %s\04" % name)
        else:
            self.log.warning('You don\'t have the privileges to delete accounts')
        return int(failure)
        
    def deletegroup(self, name):
        """Delete a group
        
        name (str) - name of group to delete
        """
        if name not in self.groups:
            self.log.error("You did not provide a valid group account, or you haven't run getgroups")
            return 1
        failure = True
        if self.privileges['deleteaccounts']:
            self.log.info('Deleting group account: %s' % name)
            failure = self._send("DELETEGROUP %s\04" % name)
        else:
            self.log.warning('You don\'t have the privileges to delete accounts')
        return int(failure)
        
    def editaccount(self, name):
        """Edit a user account specification
        
        name - update the server using the information in this account
        """
        if name not in self.accounts or self.accounts[name] == None:
            self.log.error("You did not provide a valid account, or you haven't run getaccounts and getaccountspec")
            return 1
        failure = True
        if self.privileges['editaccounts']:
            self.log.info('Editing user account: %s' % name)
            failure = self._send("EDITUSER %s\04" % self.accounts[name].getstring(self.serverprotocolversion))
        else:
            self.log.warning("You don't have the privileges to edit users")
        return int(failure)
        
    def editgroup(self, name):
        """Edit a group account specification

        name - update the server using the information in this group account
        """
        if name not in self.groups or self.groups[name] == None:
            self.log.error("You did not provide a valid group account, or you haven't run getgroups and getgroupspec")
            return 1
        failure = True
        if self.privileges['editaccounts']:
            self.log.info('Editing group account: %s' % name)
            failure = self._send("EDITGROUP %s\04" % unicode(self.groups[name].getstring(self.serverprotocolversion)))
        else:
            self.log.warning('You don\'t have the privileges to edit groups')
        return int(failure)
        
    def getaccounts(self):
        """Get a list of user accounts"""
        failure = True
        if self.privileges['editaccounts'] and not self.requested['accountlist']:
            self.log.info('Getting list of user accounts')
            self.requested['accountlist'] = True
            self.accounts = {}
            failure = self._send("USERS\04")
        elif self.requested['accountlist']:
            self.log.warning('You already have an outstanding request for the list of user accounts')
        else:
            self.log.warning('You don\'t have the privileges to get a list of user accounts')
        return int(failure)
        
    def getaccountspec(self, name):
        """Get account specification for user
        
        name (str) - name of account for which to get specification
        """
        if name not in self.accounts:
            self.log.error("You did not provide a valid user account, or you haven't run getaccounts")
            return 1
        failure = True 
        if self.privileges['editaccounts'] and name not in self.requested['readuser']:
            self.log.info('Requesting spec for user: %s' % name)
            self.requested['readuser'].append(name)
            failure = self._send("READUSER %s\04" % name)
        elif name in self.requested['readuser']:
            self.log.warning('You already have an outstanding request for a spec for this user')
        else:
            self.log.warning('You don\'t have the privileges to get a user specification')
        return int(failure)
        
    def getgroups(self):
        """Get a list of user groups"""
        failure = True
        if self.privileges['editaccounts'] and not self.requested['grouplist']:
            self.groups = {}
            self.log.info('Getting list of user groups')
            self.requested['grouplist'] = True
            failure = self._send("GROUPS\04")
        elif self.requested['grouplist']:
            self.log.warning('You already have an outstanding request for the list of group accounts')
        else:
            self.log.warning('You don\'t have the privileges to get a list of group accounts')
        return int(failure)
        
    def getgroupspec(self, name):
        """Get account specification for group
        
        name (str) - name of group account for which to get specification
        """
        if name not in self.groups:
            self.log.error("You did not provide a valid group account, or you haven't run getgroups")
            return 1
        failure = True
        if self.privileges['editaccounts'] and name not in self.requested['readgroup']:
            self.log.info('Requesting spec for group: %s' % name)
            self.requested['readgroup'].append(name)
            failure = self._send("READGROUP %s\04" % name)
        elif name in self.requested['readgroup']:
            self.log.warning('You already have an outstanding request for a spec for this group')
        else:
            self.log.warning('You don\'t have the privileges to get a group specification')
        return int(failure)
        
    ## Chat Functions
    
    def actionchatmessage(self, chatid, message):
        """Send an action message to a chat
        
        chat (int) - id of chat to which to send message
        message (str) - action chat message to send
        """
        if not self.validchat(chatid):
            self.log.error('You are not currently in that chat')
            return 1
        failure = True
        self.log.info('Sending action message to chat %s: %s' % (chatid, message))
        failure = self._send("ME %s\x1c%s\04" % (chatid, message))
        return int(failure)

    def broadcast(self, message):
        """Send a message to all users
        
        message (str) - broadcast message to send
        """
        failure = True
        if self.privileges['broadcast']:
            self.log.info('Sending broadcast message: %s' % message)
            failure = self._send("BROADCAST %s\04" % message)
        else:
            self.log.warning('You don\'t have the privileges to send a broadcast message')
        return int(failure)
        
    def changechattopic(self, chatid, topic):
        """Set a new chat topic 
        
        chatid (int) - id of chat for which to set topic
        topic (str) - new chat topic
        """
        failure = True
        if chatid not in self.chats:
            self.log.error('You are not currently in that chat')
        elif self.serverprotocolversion >= 1.1:
            if chatid != 1 or self.privileges['changetopic']:
                self.log.info('Setting topic of chat %s to %s' % (chatid, topic))
                failure = self._send("TOPIC %s\x1c%s\04" % (chatid, topic))
            else:
                self.log.warning('You don\'t have the privileges to set the chat topic for the public chat')
        else:
            self.log.warning("Server doesn't support the TOPIC command")
        return int(failure)
        
    def chatmessage(self, chatid, message):
        """Send a message to a chat
        
        chatid (int) - id of chat to which to send message
        message (str) - broadcast message to send
        """
        if not self.validchat(chatid):
            self.log.error('You are not currently in that chat')
            return 1
        failure = True
        self.log.info('Sending message to chat %s: %s' % (chatid, message))
        failure = self._send("SAY %s\x1c%s\04" % (chatid, message))
        return int(failure)
        
    def createprivatechat(self):
        """Create a private chat"""
        failure = True
        self.requested['privatechat'] += 1
        self.log.info('Creating Private Chat')
        failure = self._send("PRIVCHAT\04")
        return int(failure)
        
    def declineprivatechat(self, chatid):
        """Decline a private chat
        
        chatid (int) - id of chat to which to decline joining
        """
        failure = True
        self.log.info('Declining private chat %s' % chatid)
        failure = self._send("DECLINE %s\04" % chatid)
        del self.privatechatinvites[chatid]
        return int(failure)
        
    def getuserlist(self, chatid):
        """Get userlist for chat
        
        chatid (int) - id of chat to which to get user list
        """
        chatid = int(chatid)
        failure = True
        if chatid not in self.requested['userlist']:
            # create or empty the list of users for this chat
            self.chats[chatid] = wirechat(chatid)
            self.requested['userlist'].append(chatid)
            self.log.info('Requesting User list for chat %s' % chatid)
            failure = self._send("WHO %s\04" % chatid)
        else:
            self.log.warning('You already have or have requested the list of users for this chat')
        return int(failure)
        
    def inviteuser(self, user, chatid):
        """Inivite a user to a private chat
        
        user - user to invite
        chatid (int) - id of chat to which to invite user
        """
        userid = self.userid(user)
        if not self.validchat(chatid) or userid == None:
            self.log.error('You are not currently in that chat, or that user is not currently on the server')
            return 1
        failure = True
        if chatid == 1:
            self.log.warning('Can\'t invite users to the public chat')
        elif chatid not in self.chats:
            self.log.warning('Can\'t invite users to a chat in which you are not present')
        else:
            self.log.info('Iniviting %s to chat %s' % (self.users[userid].nick, chatid))
            failure = self._send("INVITE %s\x1c%s\04" % (userid, chatid))
        return int(failure)
        
    def joinprivatechat(self, chatid):
        """Join a private chat
        
        chatid (int) - id of chat to which to join
        """
        failure = True
        self.log.info('Joining private chat %s' % chatid)
        if not self._send("JOIN %s\04" % chatid):
            failure = self.getuserlist(chatid)
        del self.privatechatinvites[chatid]
        return int(failure)

    def leavechat(self, chatid):
        """Leave a chat
        
        chatid (int) - id of chat to which to leave
        """
        if not self.validchat(chatid):
            self.log.error('You are not currently in that chat')
            return 1
        failure = True
        self.log.info('Leaving chat %s' % chatid)
        for userid in self.chats[chatid].users:
            self.log.debug('Removing chat %s from user %s' % (chatid, userid))
            self.users[userid].removechat(chatid)
        failure = self._send("LEAVE %s\04" % chatid)
        self.log.debug('Removing chat %s' % chatid)
        del self.chats[chatid]
        if chatid == 1:
            # I don't believe that the server will disconnect you if you send
            # it a leave message with a chatid of 1, but you should only be 
            # doing this if you want to leave the server
            self.disconnect()
        return int(failure)
        
    def privatemessage(self, user, message):
        """Send a private message to a user
        
        user - user to which to send message
        message (str) - message to send to user
        """
        userid = self.userid(user)
        if userid == None:
            self.log.error('That user is not currently on the server')
            return 1
        failure = True
        self.log.info('Sending message to %s: %s' % (self.users[userid].nick, message))
        failure = self._send("MSG %s\x1c%s\04" % (userid, message))
        return int(failure)
        
    ## File Functions
    
    def createfolder(self, path):
        """Create a new folder
        
        path (str) - path at which to create folder
        """
        failure = True
        if not self.privileges['createfolders']:
            self.log.warning('You don\'t have the privileges to create folders')
        elif path in self.files or path in self.filelists:
            self.log.warning('%s already exists on the server' % path)
        else:
            # Since the server doesn't respond to a successful issue of this
            # command, we have to assume it succeeds and add the necessary entries
            # to files and filelists
            self.filelists[path] = {'revision':0, 'freeoctets':0}
            self.files[path] = wirepath(path, 1, 0, None, None)
            serverdir = os.path.dirname(path)
            if serverdir in self.files:
                self.files[path].type = self.files[serverdir].type
            if serverdir in self.filelists:
                self.filelists[path]['freeoctets'] = self.filelists[serverdir]['freeoctets']
            self.log.info('Creating new folder: %s' % path)
            failure = self._send("FOLDER %s\04" % path)
        return int(failure)
        
    def deletepath(self, path):
        """Delete a file/folder
        
        path (str) - path to delete, all deletes are recursive
        """
        failure = True
        if self.privileges['deletefiles']:
            self.log.info('Deleting path: %s' % path)
            self.forgetpath(path)
            failure = self._send("DELETE %s\04" % path)
        else:
            self.log.warning('You don\'t have the privileges to delete files/folders')
        return int(failure)
        
    def download(self, serverpath, hostpath):
        """Add a file or folder to the upload queue
        
        serverpath (str) - remote path to download
        hostpath (str) - local path at which to store downloaded files
        """
        failure = True
        hostpath, serverpath = self.normpaths(hostpath, serverpath)
        if not self.privileges['download']:
            self.log.warning("You don't have the privileges to download files/folders")
        elif not os.path.exists(os.path.dirname(hostpath)):
            self.log.warning("The folder you are are trying to download into doesn't exist")
        else:
            self.log.info('Adding %s to download queue' % serverpath)
            if serverpath in self.files:
                serverpath = self.files[serverpath]
            self.downloadqueue.insert(0,wiredownload(serverpath,hostpath))
            failure = False
            thread.start_new_thread(self.processdownloadqueue,())
        return int(failure)
        
    def getfileinfo(self, path):
        """Get info for file
        
        path (str) - path about which to get info
        """
        failure = True
        if path not in self.requested['fileinfo']:
            self.requested['fileinfo'].append(path)
            self.log.info('Requesting info for %s' % path)
            failure = self._send("STAT %s\04" % path)
        else:
            self.log.debug('Already getting info for that file')
        return int(failure)
        
    def getfilelist(self, path):
        """Get filelist for path"""
        failure = True
        if path not in self.requested['filelists']:
            self.requested['filelists'].append(path)
            if path not in self.filelists:
                self.filelists[path] = {'revision':0, 'freeoctets':0}
            else:
                self.filelists[path]['revision'] += 1
            self.log.info('Requesting file list for %s' % path)
            failure = self._send("LIST %s\04" % path)
        else:
            self.log.warning('You already have an outstanding request to get this filelist')
        return int(failure)
        
    def movepath(self, pathfrom, pathto):
        """Move a file/folder
        
        pathfrom (str) - current location of path to move
        pathto (str) - location to which to move path
        """
        failure = True
        if self.privileges['alterfiles']:
            self.log.info('Moving path %s to %s' % (pathfrom, pathto))
            self.forgetpath(pathfrom)
            failure = self._send("MOVE %s\x1c%s\04" % (pathfrom, pathto))
        else:
            self.log.warning('You don\'t have the privileges to move files/folders')
        return int(failure)
        
    def searchfiles(self, query):
        """Search for files with names containing query
        
        query (str) - search query (server will return all files containing 
            this query as a substring, I think)
        """
        failure = True
        if query not in self.requested['searchlists']:
            self.requested['searchlists'].append(query)
            self.log.info('Searching for paths containing %s' % query)
            self.searches[query] = {}
            failure = self._send("SEARCH %s\04" % query)
        else:
            self.log.debug('Already searching with that query')
        return int(failure)
        
    def setcomment(self, path, comment):
        """Set a comment on the file/folder
        
        path (str) - path on which to set comment
        comment (str) - comment for path"""
        failure = True
        if self.serverprotocolversion >= 1.1 and self.privileges['alterfiles']:
            self.log.info('Setting comment for %s: %s' % (path, comment))
            failure = self._send("COMMENT %s\x1c%s\04" % (path, comment))
        else:
            self.log.warning("Server doesn't support the COMMENT command")
        return int(failure)
        
    def settype(self, path, type):
        """Set the type of a folder
        
        path (str) - path on which to set comment
        comment (str) - comment for path"""
        failure = True
        if not isinstance(type, int) or type < 1 or type > 3:
            self.log.warning("Type is invalid, it must be an integer between 1 and 3")
        if path in self.files and self.files[path].type == 0:
            self.log.warning("Path is a file and cannot have its type changed: %s" % path)
        elif self.serverprotocolversion >= 1.1 and self.privileges['alterfiles']:
            self.log.info('Setting type for %s: %s' % (path, type))
            failure = self._send("TYPE %s\x1c%s\04" % (path, type))
        else:
            self.log.warning("Server doesn't support the TYPE command")
        return int(failure)
        
    def upload(self, hostpath, serverpath):
        """Add a file or folder to the upload queue
        
        hostpath (str) - local path to upload
        serverpath (str) - remote path at which to store uploaded files
        """
        failure = True
        hostpath, serverpath = self.normpaths(hostpath, serverpath)
        if not self.privileges['upload']:
            self.log.warning("You don't have the privileges to upload files/folders")
        elif not os.path.exists(hostpath):
            self.log.warning("You can't upload a file or folder that doesn't exist")
        else:
            self.log.info('Adding %s to upload queue' % hostpath)
            self.uploadqueue.insert(0,wireupload(hostpath, serverpath))
            failure = False
            thread.start_new_thread(self.processuploadqueue,())
        return int(failure)
        
    ## News Functions
    
    def clearnews(self):
        """Clear the news"""
        failure = True
        if self.privileges['clearnews']:
            self.log.info('Clearing the news')
            failure = self._send("CLEARNEWS\04")
            self.news = []
        else:
            self.log.warning('You don\'t have the privilages to clear the news')
        return int(failure)
        
    def getnews(self):
        """Get news"""
        failure = True
        if not self.requested['news']:
            self.requested['news'] = True
            self.log.info('Requesting news')
            # Empty the news so no duplicates appear
            self.news = []
            failure = self._send("NEWS\04")
        else:
            self.log.debug('Already requested news')
        return int(failure)
        
    def postnews(self, message):
        """Post a new news article
        
        message (str) - message to post to the news
        """
        failure = True
        if self.privileges['postnews']:
            self.log.info('Posting a new news article: %s' % message)
            failure = self._send("POST %s\04" % message)
        else:
            self.log.warning('You don\'t have the privileges to post to the news')
        return int(failure)
        
    ## User Functions

    def getuserinfo(self, user):
        """Get info on a user
        
        user - user about which to get info"""
        userid = self.userid(user)
        if userid == None:
            self.log.error('That user is not currently on the server')
            return 1
        failure = True
        if self.privileges['getuserinfo'] and userid not in self.requested['userinfo']:
            self.requested['userinfo'].append(userid)
            self.log.info('Getting info for %s' % self.users[userid].nick)
            failure = self._send("INFO %s\04" % userid)
        elif userid in self.requested['userinfo']:
            self.log.warning('You already have an outstanding request for this user\'s info')
        else:
            self.log.warning('You don\'t have the privileges to get info on users')
        return int(failure)

    def kickuser(self, user, message):
        """Kick a user
        
        user - user to kick
        message (str) - message to display when kicking user
        """
        userid = self.userid(user)
        if userid == None:
            self.log.error('That user is not currently on the server')
            return 1
        failure = True
        if self.privileges['kickusers']:
            self.log.info('Kicking user %s with comment: %s' % (self.users[userid].nick, message))
            failure = self._send("KICK %s\x1c%s\04" % (userid, message))
        else:
            self.log.warning('You don\'t have the privileges to kick users')
        return int(failure)
        
    def banuser(self, user, message):
        """Ban a user temporarily
        
        user - user to ban
        message (str) - message to display when banning user
        """
        userid = self.userid(user)
        if userid == None:
            self.log.error('That user is not currently on the server')
            return 1
        failure = True
        if self.privileges['banusers']:
            self.log.info('Banning user %s with comment: %s' % (self.users[userid].nick, message))
            failure = self._send("BAN %s\x1c%s\04" % (userid, message))
        else:
            self.log.warning('You don\'t have the privileges to kick users')
        return int(failure)
        
    ### Called on responses from server
    
    ## 2xx Informational
    
    def _gotserverinfo(self, args):
        """Received server information (200)"""
        self.log.debug('Got serverinfo')
        self.serverappversion = args[0]
        self.serverprotocolversion = float(args[1])
        self.servername = args[2]
        self.serverdescription = args[3]
        self.serverstarttime = parsewiredtime(args[4])
        if len(args) >= 6:
            self.serverfilescount = int(args[5])
            self.serverfilessize = int(args[6])
        if self.requested['connect']:
            self.requested['connect'] = False
            self.requested['login'] = True
            self.log.info('Connected to %s' % self.host)
            self.changenick(self.nick)
            self.changeicon(self.icon, self.imagefile)
            if self.status and self.serverprotocolversion >= 1.1:
                self.changestatus(self.status)
            self.log.debug('Sending client string: %s' % self.clientversionstring)
            self._send("CLIENT %s\04" % self.clientversionstring)
            self.log.debug('Logging in as: %s' % self.login)
            self._send("USER %s\04" % self.login)
            self.log.debug('Sending password')
            self._send("PASS %s\04" % self.passwordhash)
        return 0
        
    def _gotloginsucceeded(self, args):
        """Received login successful (201)"""
        if self.requested['login']:
            self.requested['login'] = False
            self.myuserid = int(args[0])
            self.log.info('Logged into %s as %s' % (self.host, self.login))
            self.getprivileges()
            self.getuserlist(1)
            return 0
        self.log.warning('Received login succeeded without attempting to login')
        return 1
    
    def _gotpong(self, args):
        """Received pong response (202)"""
        if self.requested['pong']:
            self.log.debug('Received pong in response to ping')
            self.requested['pong'] = False
            return 0
        self.log.warning('Received unrequested pong')
        return 1
        
    def _gotserverbanner(self, args):
        """Received server banner (203)"""
        if self.requested['banner']:
            self.log.info('Received server banner')
            self.serverbanner = str(args[0]).decode('base64')
            self.requested['banner'] = False
            return 0
        self.log.warning('Received unrequested server banner')
        return 1
        
    ## 3xx Chat, News, Private Messages
        
    def _gotchat(self, args):
        """Received chat message (300)"""
        chatid, userid = map(int,args[:2])
        if chatid in self.chats and userid in self.chats[chatid].users:
            self.log.info('Received message in chat %s from %s: %s' % (chatid, self.users[userid].nick,args[2]))
            return 0
        self.log.warning('Received chat message from unknown user or in unknown chat')
        return 1
        
    def _gotactionchat(self, args):
        """Received action chat message (301)"""
        chatid, userid = map(int,args[:2])
        if chatid in self.chats and userid in self.chats[chatid].users:
            self.log.info('Received action message in chat %s from %s: %s' % (chatid, self.users[userid].nick,args[2]))
            return 0
        self.log.warning('Received action chat message from unknown user or in unknown chat')
        return 1
        
    def _gotclientjoin(self, args):
        """Received client join (302)"""
        chatid, userid = map(int,args[:2])
        status = ''
        dnsname = ''
        image = None
        if chatid == 1 and userid not in self.users:
            self.log.info('%s joined server' % args[5])
            if len(args) >= 11:
                dnsname = args[8]
                status = args[9]
                image = args[10]
            self.users[userid] = wireuser(userid,args[2],args[3],args[4],args[5],args[6],args[7], dnsname, status, image)
        if chatid in self.chats:
            self.log.debug('Adding chat %s to user %s' % (chatid, userid))
            self.users[userid].addchat(chatid)
            self.log.debug('Adding user %s to chat %s' % (userid, chatid))
            self.chats[chatid].adduser(userid)
            return 0
        self.log.warning('Received a client join message for a chat we are not in')
        return 1

    def _gotclientleave(self, args):
        """Received client leave (303)"""
        chatid, userid = map(int,args[:2])
        failure, failure2 = True, True
        if chatid in self.chats and userid in self.chats[chatid].users:
            self.log.debug('Removing user %s from chat %s' % (userid, chatid))
            failure = self.chats[chatid].removeuser(userid)
        elif chatid in self.chats:
            self.log.warning('Received a client leave message for a user not in the chat')
        else:
            self.log.warning('Received a client leave message for a chat we are not in')
        if userid in self.users and chatid in self.users[userid].chats:
            self.log.debug('Removing chat %s from user %s' % (chatid, userid))
            failure2 = self.users[userid].removechat(chatid)
        elif userid in self.users: 
            self.log.warning('Received a client leave message for a user not in the chat')
        else:
            self.log.warning('Received a client leave message for an unknown user')
        if chatid == 1 and userid in self.users:
            for id in [i for i in self.users[userid].chats if i in self.chats]:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].removeuser(userid)
            self.log.info('%s left server' % self.users[userid].nick)
            self._removeuser(userid)
        return int(failure or failure2)
        
    def _gotstatuschange(self, args):
        """Received status change for user (304)"""
        userid = int(args[0])
        status = ''
        if userid in self.users:
            if len(args) >= 6:
                status = args[5]
            user = self.users[userid].updatestatus(args[1], args[2], args[3], args[4], status)
            self.log.debug('User %s status has changed' % userid)
            return 0
        self.log.warning('Got status change for user not on server')
        return 1
        
    def _gotprivatemessage(self, args):
        """Received private message (305)"""
        userid = int(args[0])
        if userid in self.users:
            self.log.info('Received private message from %s: %s' % (self.users[userid].nick,args[1]))
            return 0
        self.log.warning('Received private message from unknown user')
        return 1
        
    def _gotclientkicked(self, args):
        """Received client kicked (306)"""
        userid, kickerid = map(int, args[:2])
        if userid in self.users:
            for id in self.users[userid].chats:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].removeuser(userid)
            self.log.info('User %s was kicked by %s: %s' % (self.users[userid].nick, self.users[kickerid].nick, args[2]))
            self._removeuser(userid)
            return 0
        self.log.warning('Got client kicked message change for user not on server')
        return 1
        
    def _gotclientbanned(self, args):
        """Received client banned (307)"""
        userid, kickerid = map(int, args[:2])
        if userid in self.users:
            for id in self.users[userid].chats:
                self.log.debug('Removing user %s from chat %s' % (userid, id))
                self.chats[id].removeuser(userid)
            self.log.info('User %s was banned by %s: %s' % (userid, self.users[kickerid].nick, args[2]))
            self._removeuser(userid)
            return 0
        self.log.warning('Got client banned message change for user not on server')
        return 1
        
    def _gotuserinfo(self, args):
        """Received user info (308)"""
        userid = int(args[0])
        status = ''
        image = None
        if userid in self.requested['userinfo'] and userid in self.users:
            self.log.info('Received info for user %s' % userid)
            downloads, uploads = [], []
            if args[13] != "":
                for d in args[13].split('\x1d'):
                    dl = d.split('\x1e')
                    downloads.append({'path':dl[0], 'transferred':dl[1], 'size':dl[2], 'speed':dl[3]})
            if args[14] != "":
                for u in args[14].split('\x1d'):
                    ul = u.split('\x1e')
                    uploads.append({'path':ul[0], 'transferred':ul[1], 'size':ul[2], 'speed':ul[3]})
            if len(args) >= 17:
                status = args[15]
                image = args[16]
            self.users[userid].updatestatus(args[1], args[2], args[3], args[4], status)         
            self.users[userid].updateinfo(args[5], args[6], args[7])
            self.users[userid].updateimage(image)
            self.users[userid].updateextendedinfo(args[8], args[9], args[10], args[11], args[12], downloads, uploads)
            self.requested['userinfo'].remove(userid)
            return 0
        self.log.warning('Received user info for user not on server')
        return 1

    def _gotbroadcast(self, args):
        """Received broadcast message (309)"""
        userid = int(args[0])
        failure = False
        if userid in self.users:
            self.log.info('Received broadcast message from %s: %s' % (self.users[userid].nick,args[1]))
        elif userid == 0:
            self.log.info('Server admin has broadcast a message: %s' % args[1])
        else:
            self.log.warning('Received broadcast message from unknown user')
            failure = True
        return int(failure)
    
    def _gotuserlist(self, args):
        """Received user info (310)"""
        chatid, userid = map(int, args[:2])
        status = ''
        image = None
        if chatid in self.requested['userlist']:
            if userid not in self.users:
                if chatid == 1:
                    self.log.info('Currently Online: %s' % args[5])
                    if len(args) >= 11:
                        status = args[9]
                        image = args[10]
                    self.users[userid] = wireuser(userid,args[2],args[3],args[4],args[5],args[6],args[7],args[8], status, image)
                else:
                    self.log.warning('Got userlist for private chat %s with unknown user id: %s' % (args, userid))
                    return 1
            if chatid not in self.users[userid].chats:
                self.log.debug('Adding chat %s to user %s' % (chatid,userid))
                self.users[userid].addchat(chatid)
            if userid not in self.chats[chatid].users:
                self.log.debug('Adding user %s to chat %s' % (userid,chatid))
                self.chats[chatid].adduser(userid)
            return 0
        self.log.warning('Received unrequested userlist')
        return 1
            
    def _gotuserlistdone(self, args):
        """Finished receiving userlist (311)"""
        chatid = int(args[0])
        if chatid in self.requested['userlist']:
            self.log.info('User List Finished for Chat %s' % chatid)
            self.requested['userlist'].remove(chatid)
            return 0
        self.log.warning('Finished receiving unrequested userlist')
        return 1
        
    def _gotnews(self,args):
        """Received news article (320)"""
        if self.requested['news']:
            newsarticle = {'poster':args[0], 'posttime':parsewiredtime(args[1]), 'posttimestring':args[1], 'post':args[2]}
            self.news.append(newsarticle)
            self.log.info(u"News Article: \nposter=%(poster)s \nposttime=%(posttimestring)s \n%(post)s" % newsarticle)
            return 0
        self.log.warning('Received unrequested news article')
        return 1
        
    def _gotnewsdone(self, args):
        """Finished receiving news (321)"""
        if self.requested['news']:
            self.log.debug('Finished receiving news')
            self.requested['news'] = False
            return 0
        self.log.warning('Finished receiving unrequested news')
        return 1
        
    def _gotnewsposted(self, args):
        """New news article posted (322)"""
        newsarticle = {'poster':args[0], 'posttime':parsewiredtime(args[1]), 'posttimestring':args[1], 'post':args[2]}
        self.news.insert(0, newsarticle)
        self.log.info(u"New News Article: \nposter=%(poster)s \nposttime=%(posttimestring)s \n%(post)s" % newsarticle)
        return 0
        
    def _gotprivatechatcreated(self, args):
        """Received private chat created (330)"""
        if self.requested['privatechat'] > 0:
            self.log.info('Private Chat Created, id: %s' % args[0])
            self.getuserlist(int(args[0]))
            self.requested['privatechat'] -= 1
            return 0
        self.log.warning('Got unrequested private chat created message')
        return 1
        
    def _gotprivatechatinvite(self, args):
        """Received private chat invite (331)"""
        chatid, userid = map(int, args[:2])
        if userid in self.users:
            self.log.info('Received private chat invite from %s' % self.users[userid].nick)
            self.privatechatinvites[chatid] = {'chatid':chatid, 'user':self.users[userid]}
            return 0
        self.log.warning('Received private chat invite from unknown user')
        return 1
        
    def _gotprivatechatdeclined(self, args):
        """Received private chat declined (332)"""
        chatid, userid = map(int, args[:2])
        if chatid in self.chats and userid in self.users:
                self.log.info('%s declined to enter the private chat' % self.users[userid].nick)
                return 0
        self.log.warning('Received Private Chat Declined message for a chat in which you are not present')
        return 1
        
    def _gotclientimagechanged(self, args):
        """Received client image changed (340)"""
        userid = int(args[0])
        failure = True
        if userid in self.users:
            failure = int(self.users[userid].updateimage(args[1]))
            if failure:
                self.log.warning('Bad custom image received for %s' % self.users[userid].nick)
            else:
                self.log.debug('Received custom image change for %s' % self.users[userid].nick)
        else:
            self.log.warning('Received custom image for user who is not connected')
        return int(failure)

    def _gotchattopic(self, args):
        """Received chat topic (341)"""
        chatid = int(args[0])
        failure = True
        if chatid in self.chats:
            failure = self.chats[chatid].updatechattopic(args[1], args[2], args[3], args[4], args[5])
            self.log.info('Topic for chat %s is "%s" (set by %s)' % (chatid, args[5], args[1]))
        else:
            self.log.warning('Received chat topic for a chat in which we are not present')
        return int(failure)

    ## 4xx Files, Transfers
    
    def _gottransferready(self, args):
        """Received transfer ready (400)"""
        path = args[0]
        failure = False
        if path in self.currentdownloads:
            if int(args[1]) ==  self.currentdownloads[path].offset:
                self.log.info('Your download of %s is ready' % path)
                if path in self.requested['downloads']:
                    self.requested['downloads'].remove(path)
                self.currentdownloads[path].serverqueueposition = 0
                thread.start_new_thread(self._receivefile, (self.currentdownloads[path], args[1], args[2]))
            else:
                self.log.error('Offset offered doesn\'t match offset requested for download of ' % path)
                del self.currentdownloads[path]
                self._get()
                failure = True
        elif path in self.currentuploads:
            self.log.info('Your upload of %s is ready' % path)
            if path in self.requested['uploads']:
                self.requested['uploads'].remove(path)
            self.currentuploads[path].serverqueueposition = 0
            thread.start_new_thread(self._sendfile, (self.currentuploads[path], args[1], args[2]))
        else:
            self.log.warning('Received transfer ready for unrequested upload or download')
            failure = True
        return int(failure)
            
    def _gottransferqueued(self, args):
        """Received transfer queued (401)"""
        path, queuepos = args[:2]
        if path in self.currentdownloads:
            self.currentdownloads[path].serverqueueposition = queuepos
            self.log.info('Your download of "%s" is at position %s in the queue' % (path, queuepos))
        elif path in self.currentuploads:
            self.currentuploads[path].serverqueueposition = queuepos
            self.log.info('Your upload of "%s" is at position %s in the queue' % (path, queuepos))
        else:
            self.log.warning('Received transfer queued for unrequested transfer')
            return 1
        return 0
            
    def _gotfileinfo(self, args):
        """Received file info (402)"""
        path = args[0]
        comment = ''
        if path in self.requested['fileinfo']:
            self.log.info('Got extended file info for %s' % path)
            if path in self.files:
                del self.files[path]
            self.requested['fileinfo'].remove(path)
            if len(args) >= 7:
                comment = args[6]
            self.files[path] = wirepath(path, args[1], args[2], None, None)
            self.files[path].updateinfo(args[1], args[2], args[3], args[4], args[5], comment)
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
        
    def _gotfilelist(self, args):
        """Received file in filelist (410)"""
        folder, filename = os.path.split(args[0])
        path = args[0]
        createtime, modifytime = None, None
        if folder in self.requested['filelists']:
            self.log.info('Got info for %s' % path)
            if len(args) >= 5:
                createtime = args[3]
                modifytime = args[4]
            if path not in self.files:
                self.files[path] = wirepath(path, args[1], args[2], createtime, modifytime)
            else:
                self.files[path].updateinfo(args[1], args[2], createtime, modifytime)
            self.files[path].revision = self.filelists[os.path.dirname(path)]['revision']
            return 0
        self.log.warning('Received unrequested filelist item')
        return 1
            
    def _gotfilelistdone(self, args):
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
        
    def _gotsearchlist(self, args):
        """Received file matching search info (420)"""
        path = args[0]
        createtime, modifytime = None, None
        if self.requested['searchlists'] != []:
            self.log.info('Got search reponse: %s' % path)
            if len(args) >= 5:
                createtime = args[3]
                modifytime = args[4]
            if path not in self.files:
                self.files[path] = wirepath(path, args[1], args[2], createtime, modifytime)
            else:
                self.files[path].updateinfo(args[1], args[2],  createtime, modifytime)
            self.searches[self.requested['searchlists'][0]][path] = self.files[path]
            return 0
        self.log.warning('Received unrequested searchlist item')
        return 1
            
    def _gotsearchlistdone(self, args):
        """Finished receiving search list (421)"""
        if self.requested['searchlists'] != []:
            self.log.info('Finished getting search reponse')
            self.requested['searchlists'].pop(0)
            return 0        
        self.log.warning('Finished receiving unrequested searchlist')
        return 1
        
    ## 5xx Errors
        
    def _gotcommandfailed(self, args):
        """Received an undefined internal error prevented your command from completing (500)"""
        self.log.error('An undefined internal error prevented the server from processing your command')
        return 0

    def _gotcommandnotrecognized(self, args):
        """Received did not recognize your command (501)"""
        self.log.error('The server did not recognize your command')
        return 0
        
    def _gotcommandnotimplemented(self, args):
        """Received command not implemented by server (502)"""
        self.log.error('The command you sent has not been implemented on the server')
        return 0
        
    def _gotsyntaxerror(self, args):
        """Received there was a syntax error in your command (503)"""
        self.log.error('There was a syntax error in the command you sent')
        return 0
        
    def _gotloginfailed(self, args):
        """Received login failed (510)"""
        self.log.error('The login failed, the login and/or password is not valid')
        self.disconnect()
        return 0
        
    def _gotbanned(self, args):
        """Received banned (511)"""
        self.log.error('You have been banned from this server')
        self.disconnect()
        return 0
        
    def _gotclientnotfound(self, args):
        """Received client not found (512)"""
        self.log.error('The client you tried to access was not found')
        return 0
        
    def _gotaccountnotfound(self,args):
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
        
    def _gotaccountexists(self,args):
        """Received account already exists (514)"""
        self.log.error('The account you tried to create already exists')
        return 0
        
    def _gotcannotbedisconnected(self,args):
        """Received cannot be disconnected (515)"""
        self.log.error('The user you tried to kick or ban cannot be disconnected')
        return 0
        
    def _gotpermissiondenied(self,args):
        """Received permission denied (516)"""
        self.log.error('You lack the permissions necessary to use this command')
        return 0
        
    def _gotfilenotfound(self,args):
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
                if self._restartdownloadqueueifpathmatches(path):
                    self._restartuploadqueueifpathmatches(path)
            elif self.requested['filelists'] != []:
                path = self.requested['filelists'].pop(0)
                if self._restartdownloadqueueifpathmatches(path):
                    self._restartuploadqueueifpathmatches(path)
            elif self.requested['downloads'] != []:
                path = self.requested['downloads'].pop(0)
                self._restartdownloadqueueifpathmatches(path, True)
            elif self.requested['uploads'] != []:
                path = self.requested['uploads'].pop(0)
                self._restartuploadqueueifpathmatches(path, True)
        return 0
        
    def _gotfileexists(self,args):
        """Received file or directory already exists (521)"""
        self.log.error('The file or directory you tried to create already exists')
        if len(self.requested['uploads']) == 1:
            path = self.requested['uploads'].pop(0)
            self._restartuploadqueueifpathmatches(path, True)
        return 0
        
    def _gotchecksummismatch(self,args):
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
        
    def _gotaccountspec(self, args):
        """Received account specification for user (600)"""
        accountname = args[0]
        if accountname in self.requested['readuser']:
            self.log.info('Got account spec for user: %s' % accountname)
            self.accounts[accountname] = wireuseraccount(accountname, args[1], args[2], wireprivileges(args[3:]))
            self.requested['readuser'].pop(0)
            return 0
        self.log.warning('Received account specification for user without requesting it')
        return 1
    
    def _gotgroupspec(self, args):
        """Received account specification for group (601)"""
        accountname = args[0]
        if accountname in self.requested['readgroup']:
            self.log.info('Got account spec for group: %s' % accountname)
            self.groups[accountname] = wiregroupaccount(accountname, wireprivileges(args[1:]))
            self.requested['readgroup'].pop(0)
            return 0
        self.log.warning('Received account specification for group without requesting it')
        return 1
        
    def _gotprivileges(self,args):
        """Received privileges for this connection (602)"""
        self.log.debug('Got privileges for this connection')
        self.privileges.update(args)
        maxsimultaneousdownloads = self.privileges['downloadlimit']
        maxsimultaneousuploads = self.privileges['uploadlimit']
        if maxsimultaneousdownloads > 0 and maxsimultaneousdownloads < self.maxsimultaneousdownloads:
            self.maxsimultaneousdownloads = maxsimultaneousdownloads
        if maxsimultaneousuploads > 0 and maxsimultaneousuploads < self.maxsimultaneousuploads:
            self.maxsimultaneousuploads = maxsimultaneousuploads
        return 0
        
    def _gotaccountlist(self,args):
        """Received account name (610)"""
        accountname = args[0]
        if self.requested['accountlist']:
            self.log.info('Got account: %s' % accountname)
            if accountname not in self.accounts:
                self.accounts[accountname] = None
                return 0
        self.log.warning('Received account list without requesting it')
        return 1
        
    def _gotaccountlistdone(self, args):
        """Finished receiving account list (611)"""
        if self.requested['accountlist']:
            self.log.info('Finished receiving account list')
            self.requested['accountlist'] = False
            return 0
        self.log.warning('Got account list done for already finished account list')
        return 1
        
    def _gotgrouplist(self,args):
        """Received group name (620)"""
        accountname = args[0]
        if self.requested['grouplist']:
            self.log.info('Got group %s' % accountname)
            if accountname not in self.groups:
                self.groups[accountname] = None
            return 0
        self.log.warning('Received group list without requesting it')
        return 1
        
    def _gotgrouplistdone(self, args):
        """Finished receiving group list (621)"""
        if self.requested['grouplist']:
            self.log.info('Finished receiving group list')
            self.requested['grouplist'] = False
            return 0
        self.log.warning('Got group list done for already finished group list')
        return 1
        
    ## Command Not Recognised
        
    def _gotunrecognizedmessage(self, servermessage):
        """Received unrecognized message"""
        self.log.warning('Received unrecognized message from server')
        return 0

### Function decorators

def _lockdeco(function):
    """Acquire the lock before the function call, and release it after"""
    def new_function(self, *args, **kwargs):
        acquired = self.acquirelock()
        try:
            returnobj = function(self, *args, **kwargs)  
        finally:
            self.releaselock(acquired)
        return returnobj
    #new_function.func_name = function.func_name
    new_function.__doc__ = function.__doc__
    return new_function
    
def _gotmessagedeco(function):
    """Only allow the _listen thread to call got* functions"""
    def new_function(self, *args, **kwargs):
        assert thread.get_ident() == self.listenid
        return function(self, *args, **kwargs)
    #new_function.func_name = function.func_name
    new_function.__doc__ = function.__doc__
    return new_function

## Wrap functions using function decorators

lockfunctions = '''clearuploadqueue cleardownloadqueue 
forgetpath processdownloadqueue processuploadqueue restorequeues savequeues 
changeicon changenick changestatus connect disconnect getbanner getprivileges 
createaccount creategroup deleteaccount deletegroup editaccount editgroup 
getaccounts getaccountspec getgroups getgroupspec actionchatmessage broadcast 
changechattopic chatmessage createprivatechat declineprivatechat getuserlist 
inviteuser joinprivatechat leavechat privatemessage createfolder deletepath 
download getfileinfo getfilelist movepath searchfiles setcomment settype 
upload clearnews getnews postnews getuserinfo kickuser banuser'''.split()
for function in lockfunctions:
    wire.__dict__[function] = _lockdeco(wire.__dict__[function])

for function in wire.__dict__:
    if function.startswith('_got') and callable(wire.__dict__[function]):
        wire.__dict__[function] = _gotmessagedeco(wire.__dict__[function])