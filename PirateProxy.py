#!/usr/bin/env python
"""Usage: python ArchiverProxy.py [[--kill | --help | port] [HTTP-PROXY]]
An http proxy server which archives all your HTTP traffic.
http://logicerror.com/archiverProxy

  --kill	   Kill all other proxies and exit
  port		 The port on which to run the proxy (default %(PORT)d)
  HTTP-PROXY   The URL of another HTTP proxy to use"""

__version__ = "0.56 (World Traveler)"
# Thanks to DanC for the EWOULDBLOCK patch!

__author__  =   "Aaron Swartz <http://www.aaronsw.com/>"
__credits__ = """with help from Sean B. Palmer <http://purl.org/net/sbp/>
based on an idea by Gerald Oskoboiny <http://impressive.net/people/gerald/>

Code based on AsyncMojoProxy.py,v 1.13 2000/11/14 23:56:30 nejucomo Exp
http://cvs.sf.net/cgi-bin/viewcvs.cgi/mojonation/evil/proxy/AsyncMojoProxy.py
which, in turn is:
based on a combination of code from the following sources:
  the medusa tutorial at http://www.nightmare.com/medusa/index.html
  munchy.py by Neil Schemenauer <nascheme@enme.ucalgary.ca>
"""

__copyright__ = "This program is free software."

"""
REVISION HISTORY:
 - 0.55 (World Traveler)
   Many cosmetic improvements and fixes
   Added an "off" mode
   Supports long file names
   Fixed a bug where it'd encode filenames on all systems (not just Windows)
   
 - Turned it to PirateProxy. Only saves mp3s and runs a tagger on any mp3s.

 - ...previous versions...
   Maybe I'll add these someday.
	
TODO: 
 - Delete duplicate files
 - Give the archived files file name extensions (.txt, .html, etc.)
 - Provide easy way to view archived pages, links from error messages
	 - Do a redirect to the archived version if the Referer is from an archived page
 - Integrate code better with the object model
 - Abstract out archiver-specific parts through callbacks
 - Put it in CVS somewhere?
 
NEXT STEPS:
 - Make it a real caching proxy (like Squid, etc.)
 - Add a page-prefetcher to speed browsing
 - Use it as a backend for <http://logicerror.com/betterPURLs>

Based on AsyncMojoProxy.py,v 1.13 2000/11/14 23:56:30 nejucomo Exp
http://cvs.sf.net/cgi-bin/viewcvs.cgi/mojonation/evil/proxy/AsyncMojoProxy.py
which, in turn is:
based on a combination of code from the following sources:
  the medusa tutorial at http://www.nightmare.com/medusa/index.html
  munchy.py by Neil Schemenauer <nascheme@enme.ucalgary.ca>
"""

#####################################################################
# Start user configuration
#####################################################################

# default port if none specified on command line
PORT = 8119

# Only save files with this content type prefixes (always lowercase)
ACCEPTED_CONTENT_TYPES = ['audio/mpeg', 'video/x-flv', 'video/mp4']
FILE_EXTENSIONS = {'audio/mpeg':'.mp3', 'video/x-flv':'.flv', 'video/mp4':'.mp4'}

# Tagger rename pattern
# %A (artist), %a (album), %t (title), %n (track number),
# and %N (total number of tracks)

TAGGER_PATTERN = '%A - %t'

# debugging level,
#	0 = no debugging, only notices
#	1 = access and error debugging
#	2 = full debugging
#	3 = really full debugging
DEBUG_LEVEL = 1

SHOW_ERRORS = 1

# the address to bind the server to
ADDR_TO_BIND_TO = '127.0.0.1'

DOMAIN_ONLY_DIRS = True

# Use date-stamped filenames or plain numbered ones?
ARCHIVE_FILE_NAMES = 'plain'
# ARCHIVE_FILE_NAMES = 'date'

# Start in archiving mode or in viewing mode?
ARCHIVE_ACTION_MODE = 'archive'
#ARCHIVE_ACTION_MODE = 'view'
#ARCHIVE_ACTION_MODE = 'off'

ARCHIVE_ACTION_NAMES = {
	'archive':'Archiving',
	'view':'Viewing',
	'off':'Off'
}

ARCHIVE_MAXIMUM_FILE_SIZE = 127

#####################################################################
# End of user configuration
#####################################################################

import sys
import os
import time
import string
import re
import random
import binascii
import traceback
import stat
from hashlib import md5

import BaseHTTPServer
import urlparse
import mimetools
from stat import ST_MTIME
from cStringIO import StringIO

import socket
import asyncore
import asynchat
from errno import EWOULDBLOCK
from StringIO import StringIO

import eyeD3	

###############################################################################
def log(s, v=1, args=None):
	if v <= DEBUG_LEVEL:
		if args:
			sys.stdout.write(s % args)
		else:
			sys.stdout.write(s)

def handle_error(self):
	if (sys.exc_type == socket.error and (sys.exc_value[0] == 32 or sys.exc_value[0] == 9)) or (
		sys.exc_type == AttributeError):
		# ignore these errors
		self.handle_close() # something is pretty broken, close it
		return
	if DEBUG_LEVEL > 0 or SHOW_ERRORS:
		print time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())), "An error has occurred: \r\n"
		traceback.print_exception(sys.exc_type,sys.exc_value, sys.exc_traceback)
	else:
		e = open('errors.txt','a')
		e.write(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())) + ' An error has occurred: \r\n')
		traceback.print_exception(sys.exc_type,sys.exc_value, sys.exc_traceback, file=e)
		e.write('\r\n')
		e.close()
		log('An error occurred, details are in errors.txt\n', v=0)
		
###############################################################################
# This is the section that is archiver-specific...

archive_files = {}	# File in which to write the data
archive_status = {} # Status of the connection 
# (headers if it's not there, None if we shouldn't log it, otherwise 'body')

# Tagger options
#options = {'unique_file_ids': None, 'field_delim': ':', 'showGenres': None, 'lyrics': None, 'run_profiler': None, 'nocolor': None, 'url_frames': [], 'remove_images': None, 'convertVersion': 0, 'remove_all': 0, 'year': None, 'images': None, 'user_url_frames': [], 'jep_118': None, 'album': None, 'no_tdtg': 0, 'textFrames': [], 'title': None, 'remove_v2': 0, 'comments': None, 'strict': None, 'play_count': None, 'lametag': None, 'zeropad': True, 'track': None, 'fs_encoding': 'utf-8', 'objects': None, 'genre': None, 'verbose': None, 'writeImages': None, 'publisher': None, 'rename_pattern': TAGGER_PATTERN, 'artist': None, 'nfo': None, 'showImagesTypes': None, 'force_update': 0, 'bpm': None, 'track_total': None, 'textEncoding': None, 'remove_v1': 0, 'remove_comments': None, 'writeObjects': None, 'tagVersion': 48, 'debug': None, 'remove_lyrics': None, 'userTextFrames': []}
#
class Mp3Tagger(object):
	def __init__(self):
		self.fs_encoding = sys.getfilesystemencoding();
	
	def is_mp3_file(self, filename):
		return eyeD3.isMp3File(filename)

	def tagstring_to_fname(self, tagstring):
		enc = self.fs_encoding
		return tagstring.encode(enc,'replace') + '.mp3'

	def rename(self, filename, pattern):
		log(filename + " is an mp3... running tagger" + '\n', v=1)
		dir = os.path.dirname(filename)
		try:
			f = eyeD3.tag.Mp3AudioFile(filename, eyeD3.ID3_ANY_VERSION);
			name = f.getTag().tagToString(pattern);

			# find a unique file name
			fnbuild = lambda tagstr: os.path.join(dir, self.tagstring_to_fname(name))
			fromtags = name
			i = 1
			while os.path.exists(fnbuild(name)):
				name = fromtags +  ' - ' + str(i)
				i += 1
			
			log("Renaming to " + fnbuild(name) + '\n', v=1)
			f.rename(name, self.fs_encoding);
			return True
		except eyeD3.TagException, ex:
			log(str(ex) + '\n', v=1);
			
		return False

tagger = Mp3Tagger();

def re_exact_match(pattern, string):
	m = re.match(pattern, string)
	if m is None:
		return False
	return m.start() == 0 and m.end() == len(string)	
	

def keep_only_domain(webpath):
	print webpath
	# Isolate the domain
	if len(webpath) < 2:
		return webpath
	domain = webpath[1]
	# Throw away usernames
	if domain.find('@') >= 0:
		i = domain.index('@')
		domain = domain[i+1:]
	# for everything except ipv4 addresses
	# keep only the last two parts (eg. static.farm.youtube.com => youtube.com)
	if not re_exact_match('([0-9]{1,3}\.){3}[0-9]{1,3}', domain):
		domain = '.'.join(domain.split('.')[-2:])
	return ['http', domain]
	
	

def archive_url2filename(url, makeNew=1):
	dirname = url
	dirname = string.replace(dirname, '://', os.sep, 1)
	dirname = string.replace(dirname, '/', os.sep)
	if dirname[-1:] == os.sep:
		dirname += 'index'
	
	if os.name == 'dos' or os.name == 'nt':
		for c in [':', '*', '?', '"', '<', '>', '|']:
			dirname = string.replace(dirname, c, '%'+string.upper(binascii.b2a_hex(c)))

	dirname2 = string.split(dirname, os.sep)
	if DOMAIN_ONLY_DIRS:
		dirname2 = keep_only_domain(dirname2)
	for i in range(len(dirname2)):
		if len(dirname2[i]) > ARCHIVE_MAXIMUM_FILE_SIZE:
			dirname2[i] = md5(dirname2[i]).hexdigest()
	
	dirname = string.join(dirname2, os.sep)

	# Find a unique name in case of collisions:
	if makeNew and not os.path.isdir(dirname):
		while os.path.exists(dirname) and not os.path.isdir(dirname):
			dirname += '_'

		os.makedirs(dirname)
		log('Making directory: '+dirname+'\n', v=2)
	
	if makeNew:
		if ARCHIVE_FILE_NAMES == 'time':
			# Find a unique filename based on time:
			time_i = string.split(str(time.time()), '.')[0]
			i = 0
			filename = str(time_i) + '.headers'
			while filename in os.listdir(dirname):
				i += 1
				filename = str(time_i) + '.' + i + '.headers'
		else:
			# Find a unique filename with a number:
			i = 1
			while str(i) + '.headers' in os.listdir(dirname):
				i += 1
			filename = str(i) + '.headers'
	else:
		if not os.access(dirname, os.F_OK): return 404 # directory doesn't exist
		filename = "-1"
		for file in os.listdir(dirname):
			if (file.isdigit() # ASSUMPTION: all archived files have numeric names
				and int(file) > int(filename) # get the biggest file
				and len(open(os.path.join(dirname, file)).read())): # it has content
				filename = file
		
		if filename == "-1": return 404
	
	return os.path.join(dirname, filename)


def extract_content_type(headers):
	headers = headers.replace('\r', '\n').lower()
	lines = headers.split('\n')
	content_types = [i for i in lines if i.find('content-type:') >= 0]
	try:
		content_type = content_types[0].split()
		return content_type[1]
	except:
		# No content type header found.
		return None 

def content_type_accepted(content_type):
	if content_type is None:
		return False
		
	for i in ACCEPTED_CONTENT_TYPES:
		if content_type.startswith(i):
			return True
	return False
		

def archive_connection(klass, request, url, data):
	filename = None
	if not archive_files.has_key(klass):
		# Use a StringIO object to hold the header and store it in the dictionary:
		f = StringIO()
		archive_files[klass] = [f, None]

		# Clean the request header:
		request = string.replace(request, '\r', '')
		request = string.replace(request, '\n', '')

		# Write out the URL/date header:
		f.write(request + ' ' + 
			 time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())) 
			 + '\r\n')
		
	else:
		f, filename = archive_files[klass]
	
	# File should not be saved
	if f == None:
		return
	
	if not archive_status.has_key(klass) and string.find(data, '\r\n\r\n'):		
		# We've found the end of the headers
		n = string.find(data, '\r\n\r\n')
		f.write(data[:n+4])
		content_type = extract_content_type(data[:n+4])
		# Discard the file if it's not among the accepted content-types:
		if not content_type_accepted(content_type):
			log('Discarding ' + url + ' -- content type not for archival\n', v=2)
			archive_files[klass] = [None, None]
			archive_status[klass] = None
			return
		
		# Create the directory name based on the URL
		filename = archive_url2filename(url)
		
		# Store the stringIO object to a real file.
		log('Opening file: '+filename+'\n', v=2)
		hf = open(filename, 'w')
		hf.write(f.getvalue())
		hf.close()
		f.close()
		
		# Switch to the data file
		data = data[n+4:]
		filename = filename[:-len('.headers')]
		filename = filename + FILE_EXTENSIONS[content_type]
		log('Switching to file: '+filename+' -- end of headers\n', v=2)
		f = open(filename, 'w')
		archive_files[klass][0] = f
		archive_files[klass][1] = filename
		archive_status[klass] = 'body'
	
	f.write(data)

def archive_handle_request(self):
	global ARCHIVE_ACTION_MODE
	filename = self.path[1:]
	filename = string.replace(filename, '/', os.sep)

	if self.path in ['/', '/mode-view', '/mode-archive', '/mode-off']: # @@KLUDGE: this should be done with a real POST but I can't figure out how to read the POST contents without a lot of pain :-(
		if self.method == 'POST':
			if self.path == '/mode-view': ARCHIVE_ACTION_MODE = 'view'
			elif self.path == '/mode-archive': ARCHIVE_ACTION_MODE = 'archive'
			elif self.path == '/mode-off': ARCHIVE_ACTION_MODE = 'off'
		
		out = """<p>This is the <a href="http://logicerror.com/archiverProxy">Archiver Proxy</a>. It archives the contents of every page you visit, and allows you to view them at a later date.</p>
		"""
		
		for mode in ['archive', 'view', 'off']:
			if mode == ARCHIVE_ACTION_MODE:
				out += '<p>You are currently: <strong>' + ARCHIVE_ACTION_NAMES[mode] + '</strong>.</p>'
			else:
				out += '<form method="post" action="mode-' + mode + '">Switch to: <input type="submit" name="mode" value="' + ARCHIVE_ACTION_NAMES[mode] + '" /></form>'
		
		out += '<p>You can also <a href="http/">browse your archived pages</a>.</p>'
		self.show_response(200, out, 'Archiver Proxy Home')
		
	elif not os.access(filename, os.F_OK):
		self.show_response(404, "The file you requested could not be found.")
	elif stat.S_ISDIR(os.stat(filename)[stat.ST_MODE]):
		listing = os.listdir(filename)
		dirpath = ''
		dircode = '</p>'
		dirlist = string.split(filename, os.sep)
		dirlist.reverse()
		for dir in dirlist:
			if dir == "": continue
			dircode = ' <a href="' + dirpath + '">' + dir + '</a> ' + os.sep + dircode
			dirpath += '../'
		dircode = '<p> / ' + dircode
		out = dircode + '\n'
		out += """<p>Please select a directory or file to view:</p>
		
		<ul>"""
		for item in listing:
			line = ""
			if item[-8:] == '.headers': continue  # Don't display the header files
			line += '\n	<li><a href="'
			if not stat.S_ISREG(os.stat(os.path.join(filename, item))[stat.ST_MODE]): item += os.sep
			line += item + '">' + item + '</a></li>'
			out += (line+'\n')
		out += ('</ul>\n')
		
		self.show_response(200, out, "File Browser")

	elif stat.S_ISREG(os.stat(filename)[stat.ST_MODE]):
		h = open(filename + '.headers').readlines()[1:]
		for line in h:
			self.push(line)
		del h
		d = open(filename).readlines()
		for line in d:
			self.push(line)
		
	else: 
		self.show_response(500, "<strong>An internal error has ocurred:</strong> The file you selected is not valid.\n", "Internal Error")

def archive_close(klass):
	filename = None
	if archive_files.has_key(klass):
		filename = archive_files[klass][1]
		del archive_files[klass]
		
	if archive_status.pop(klass, None):
		log('Closed file: ' + filename + '\n', v=1)
		if tagger.is_mp3_file(filename):
			tagger.rename(filename, TAGGER_PATTERN)


def archive_view(self):
	log("Viewing URI: <" + self.url + ">", v=3)
	filename = archive_url2filename(self.url, makeNew=0)
	if filename == 404:
		self.show_response(404, "The URI <code>" + self.url + "</code> could not be found.")
		return
	h = open(filename + '.headers').readlines()[1:]
	for line in h:
		self.push(line)
	del h
	d = open(filename).readlines()
	for line in d:
		self.push(line)


###############################################################################
def sameHost(host, port, HOST, PORT):
	if port == PORT and (
		(HOST == '' and (host == '127.0.0.1' or string.lower(host) == 'localhost')) 
		or string.lower(host) == string.lower(HOST)):
		return 1
	else: return 0

###############################################################################
class AsyncProxyError(StandardError): pass


###############################################################################
class AsyncHTTPProxySender(asynchat.async_chat):
	def __init__(self, receiver, id, host, port):
		asynchat.async_chat.__init__(self)
		self.receiver = receiver
		self.id = id
		self.set_terminator(None)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port
		try:
			self.connect( (host, port) )
		except socket.error, e:
			if e[0] is EWOULDBLOCK: log("@@DanC hack"); return
			log('(%d) XXX %s\n' % (self.id, e))
			self.receiver.sender_connection_error(e)
			self.close()
			return

	def handle_connect(self):
		log('(%d) S handle_connect\n' % self.id, 3)
		try:
			if sys.platform != 'win32':
				self.socket.recv(0)  # check for any socket errors during connect
			self.receiver.sender_is_connected()
		except socket.error, e:
			log('(%d) OOO %s\n' % (self.id, e))
			if hasattr(self, 'receiver'):
				self.receiver.sender_connection_error(e)
			self.close()
			return
		log('(%d) sender connected\n' % self.id, 2)

	def return_error(self, e):
		log('(%d) sender got socket error: %s\n', args=(self.id, e), v=2)
		if isinstance(e, socket.error) and type(e.args) == type(()) and len(e.args) == 2:
			e = e.args[1]  # get the error string only
		self.receiver.error(404, 'Error connecting to <em>%s</em> on port <em>%d</em>: <b>%s</b>' % (self.host, self.port, e), response=str(e))
		self.close()

	def collect_incoming_data(self, data):
		if DEBUG_LEVEL >= 3:
			log('==> (%d) %s\n', args=(self.id, repr(data)), v=3)
		else:
			log('==> (%d) %d bytes\n', args=(self.id, len(data)), v=2)
		if ARCHIVE_ACTION_MODE != 'off':
			archive_connection(self, self.receiver.request, self.receiver.url, data)

		self.receiver.push(data)

	def handle_close(self):
		log('(%d) sender closing\n' % self.id, v=2)
		if hasattr(self, 'receiver'):
			self.receiver.close_when_done()
			del self.receiver  # break circular reference
		if ARCHIVE_ACTION_MODE != 'off':
			archive_close(self)
		self.close()

	def handle_error(self):
		handle_error(self)
	
	def log(self, message):
		log('(%d) sender: %s\n', args=(self.id, message,), v=1)
	
	def log_info(self, message, type='info'):
		if __debug__ or type != 'info':
			log('%s: %s' % (type, message), v=0)
	

###############################################################################
class AsyncHTTPProxyReceiver(asynchat.async_chat):
	channel_counter = [0]

	def __init__(self, server, (conn, addr)):
		self.id = self.channel_counter[0]  # used during log calls
		try:
			self.channel_counter[0] = self.channel_counter[0] + 1
		except OverflowError:
			self.channel_counter[0] = 0
		asynchat.async_chat.__init__(self, conn)
		self.set_terminator('\n')
		self.server = server
		self.buffer = StringIO()

		# in the beginning there was GET...
		self.found_terminator = self.read_http_request
	
	def collect_incoming_data(self, data):
		self.buffer.write(data)
	
	def push_incoming_data_to_sender(self, data):
		if DEBUG_LEVEL >= 3:
			log('<== (%d) %s\n', args=(self.id, repr(data)), v=3)
		else:
			log('<== (%d) %d bytes\n', args=(self.id, len(data)), v=2)
		self.sender.push(data)

	#### to be used as a found_terminator method
	def read_http_request(self):
		self.request = self.buffer.getvalue()
		self.buffer = StringIO()

		log('%s - %s\n', args=(time.ctime(time.time()), self.request), v=1)

		# client-originated shutdown hack:
		if string.strip(self.request) == 'quit':
			log('External quit command received.\n')
			# On pre python 2.0 this will raise a NameError,
			# but asyncore will handle it well.  On 2.0, it
			# will cause asyncore to exit.
			raise asyncore.ExitNow

		try:
			self.method, self.url, self.protocol = string.split(self.request)
			self.method = string.upper(self.method)
		except:
			self.error(400, "Can't parse request")
		if not self.url:
			self.error(400, "Empty URL")
		if self.method not in ['CONNECT', 'GET', 'HEAD', 'POST', 'PUT']:
			self.error(501, "Unknown request method (%s)" % self.method)
		if self.method == 'CONNECT':
			self.netloc = self.url
			self.scheme = 'https'
			self.path = ''
			params, query, fragment = '', '', ''
		else:
			if self.url[0] == '/':
				self.path = self.url
			else:
				# split url into site and path
				self.scheme, self.netloc, self.path, params, query, fragment = urlparse.urlparse(self.url)
				if string.lower(self.scheme) != 'http':
					self.error(501, "Unknown request scheme (%s)" % self.url) #, self.scheme)

				# find port number
				if ':' in self.netloc:
					self.host, self.port = string.split(self.netloc, ':')
					self.port = string.atoi(self.port)
				else:
					self.host = self.netloc
					if self.method == 'CONNECT':
						self.port = 443  # default SSL port
					else:
						self.port = 80
				self.path = urlparse.urlunparse(('', '', self.path, params, query, fragment))

		self.rawheaders = StringIO()  # a "file" to read the headers into for mimetools.Message
		self.found_terminator = self.read_http_headers

	#### to be used as a found_terminator method
	def read_http_headers(self):
		header = self.buffer.getvalue()
		self.buffer = StringIO()
		if header and header[0] != '\r':
			self.rawheaders.write(header)
			self.rawheaders.write('\n')
		else:
			# all headers have been read, process them
			self.rawheaders.seek(0)
			self.mimeheaders = mimetools.Message(self.rawheaders)
			if (self.method == 'POST' or self.method == 'PUT') and not self.mimeheaders.has_key('content-length'):
				self.error(400, "Missing Content-Length for %s method" % self.method)
			self.length = int(self.mimeheaders.get('content-length', 0))
			del self.mimeheaders['accept-encoding']
			del self.mimeheaders['proxy-connection']
			
			# check to see if we want to handle a request by the archiver
			if self.url[0] == '/' or sameHost(self.host, self.port, ADDR_TO_BIND_TO, PORT):
				archive_handle_request(self)
				self.handle_close()
				return

			if ARCHIVE_ACTION_MODE == 'view':
				archive_view(self)
				self.handle_close()
				return
			
			# determine the next hop (another proxy or the remote host) and open a connection
			http_proxy = os.environ.get('http_proxy')
			if not http_proxy :
				http_proxy = os.environ.get('HTTP_PROXY')
			# if we're chaining to another proxy, modify our request to do that
			if http_proxy:
				scheme, netloc, path, params, query, fragment = urlparse.urlparse(http_proxy)
				if string.lower(scheme) == 'http' :
					log('using next http proxy: %s\n' % netloc, 2)
					# set host and port to the proxy
					if ':' in netloc:
						self.host, self.port = string.split(netloc, ':')
						self.port = string.atoi(self.port)
					else:
						self.host = netloc
						self.port = 80
					# replace the path within the request with the full URL for the next proxy
					self.path = self.url

			# create a sender connection to the next hop
			self.sender = AsyncHTTPProxySender(self, self.id, self.host, self.port)

			# send the request to the sender (this is its own method so that the sender can trigger
			# it again should its connection fail and it needs to redirect us to another site)
			self.push_request_to_sender()
	
	def push_request_to_sender(self):
		request = '%s %s HTTP/1.0\r\n%s\r\n' % (self.method, self.path, string.join(self.mimeheaders.headers, ''))

		if http_proxy:
			log('(%d) sending request to the next http proxy:\n' % self.id, v=2)
		else:
			log('(%d) sending request to server:\n' % self.id, v=2)
		log(request, v=2)

		# send the request and headers on through to the next hop
		self.sender.push(request)

		# no more formatted IO, just pass any remaining data through
		self.set_terminator(None)

		# buffer up incoming data until the sender is ready to accept it
		self.buffer = StringIO()
	
	def sender_is_connected(self):
		"""
		The sender calls this to tell us when it is ready for more data
		"""
		log('(%d) R sender_is_connected()\n' % self.id, v=3)
		# sender gave is the OK, give it our buffered data and any future data we receive
		self.push_incoming_data_to_sender(self.buffer.getvalue())
		self.buffer = None
		self.collect_incoming_data = self.push_incoming_data_to_sender
	
	def sender_connection_error(self, e):
		log('(%d) R sender_connection_error(%s) for %s:%s\n' % (self.id, e, self.host, self.port), v=2)
		if isinstance(e, socket.error) and type(e.args) == type(()) and len(e.args) == 2:
			e = e.args[1]  # get the error string only
		self.error(404, 'Error connecting to <em>%s</em> on port <em>%d</em>: <b>%s</b>' % (self.host, self.port, e), response=str(e))

	def handle_close(self):
		log('(%d) receiver closing\n' % self.id, v=2)
		if hasattr(self, 'sender'):
			# self.sender.close() should be fine except for PUT requests?
			self.sender.close_when_done()
			del self.sender  # break circular reference
		self.close()
	
	def show_response(self, code, body, title=None, response=None):
		if not response:
			response = BaseHTTPServer.BaseHTTPRequestHandler.responses[code][0]
		if not title:
			title = str(code) + ' ' + response
		self.push("HTTP/1.0 %s %s\r\n" % (code, response))
		self.push("Server: http://logicerror.com/archiverProxy\r\n")
		self.push("Content-type: text/html\r\n")
		self.push("\r\n")
		out = "<html><head>\n<title>" + title + "</title>\n</head>\n"
		out += '<body><h1>' + title +'</h1>\n'
		out += body 
		out += '<hr />\n<address><a href="%s">Archiver Proxy %s</a></address>' % (self.server.oururi, __version__)
		out += '\n</body>\n</html>'
		i = 0
		for j in range(len(out) / 512):
			self.push(out[i:i+512]) # push only 512 characters at a time
			i += 512
		self.push(out[i:]) # push out the rest

	def error(self, code, body, response=None):
		self.show_response(code, body, response=response)
		if hasattr(self, 'sender'):
			self.sender.handle_close()
			del self.sender  # break circular reference
		self.close()
		# asyncore.poll() catches this	(XXX shouldn't need this?)
		#raise AsyncProxyError, (code, body)

	def handle_error(self):
		handle_error(self)

	def log(self, message):
		log('(%d) receiver: %s\n', args=(self.id, message,), v=1)

	def log_info (self, message, type='info'):
		if __debug__ or type != 'info':
			log('%s: %s' % (type, message))


###############################################################################
class AsyncHTTPProxyServer(asyncore.dispatcher):
	def __init__(self, port):
		asyncore.dispatcher.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.ouraddr = (ADDR_TO_BIND_TO, port)
		self.oururi = "http://%s:%d/" % self.ouraddr
		log('Starting proxy at %s\n' % self.oururi, 0)
		self.bind(self.ouraddr)
		self.listen(5)

	def handle_accept(self):
		AsyncHTTPProxyReceiver(self, self.accept())
	
	def log(self, message):
		log('server: %s\n', args=(message,), v=1)

	def handle_error(self):
		handle_error()

###############################################################################
def kill_external_proxy():
	"""
	Kills all external instances of the proxy owned by this user.

	This is a wrapper for the platform specific version.
	"""
	log("Stopping external proxies:\n")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		try:
			s.connect(('localhost', 8000))
			s.send('quit\r\n')
		finally:
			s.close()
	except:
		log('Could not connect to locahost 8000, oh well...\n')
	
def kill_external_proxy_win32():
	import win32api, win32pdhutil, win32con
	# XXX This code was taken from the Python1.6 Windows distribution.

	# Change suggested by Dan Knierim, who found that this performed a
	# "refresh", allowing us to kill processes created since this was run
	# for the first time.
	try:
		win32pdhutil.GetPerformanceAttributes(
			'Process','ID Process','archiverproxy')
	except:
		pass

	try:
		pids = win32pdhutil.FindPerformanceAttributesByName('archiverproxy')
	except:
		log("Not enough win32pdh library calls supported on this OS\n")
		log("older archiverproxy processes will not be automatically killed.\n")
		return

	# If _my_ pid in there, remove it!
	try:
		pids.remove(win32api.GetCurrentProcessId())
	except ValueError, e:
		log("Strange, this proxy wasn't in the process list.\n")
		pass

	if pids:
		for pid in pids:
			log("Attempting to terminate pid "+str(pid)+"...\n")
			handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
			win32api.TerminateProcess(handle,0)
			win32api.CloseHandle(handle)
	else:
		log("No external proxies found.\n")
	
if __name__ == '__main__':
	if len(sys.argv) >= 2 and sys.argv[1] == '--kill':
		# Kill the other proxies:
		kill_external_proxy()
		log("Exiting.\n")
		raise SystemExit
	elif len(sys.argv) >= 2 and sys.argv[1] == '--help':
		print __doc__ % {'PORT':PORT}
		print
		print "Version: " + __version__
		raise SystemExit

	# get the port if specified
	if len(sys.argv) >= 2:
		PORT = int(sys.argv[1])

	if len(sys.argv) > 3 :	# 3th param: the next-step HTTP proxy can specified here (overrides the environment variable)
		os.environ['http_proxy'] = sys.argv[3]
	# display which proxy we're using
	http_proxy = os.environ.get('http_proxy')
	if not http_proxy :
		http_proxy = os.environ.get('HTTP_PROXY')
	
	if http_proxy :
		log("Next hop proxy: %s\n" % http_proxy, 0)
		scheme, netloc, path, params, query, fragment = urlparse.urlparse(http_proxy)
		# set host and port to the proxy
		if ':' in netloc:
			host, port = string.split(netloc, ':')
			port = string.atoi(port)
		else:
			host = netloc
			port = 80
		
		# do a basic checks to prevent a proxy loop
		if sameHost(host, port, ADDR_TO_BIND_TO, PORT):
			raise SystemExit, "Next hop proxy cannot be myself"

	ps = AsyncHTTPProxyServer(PORT)
	log("Starting service...\n")
	
	asyncore.loop()
