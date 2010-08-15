#!/usr/bin/env python
"""Usage: python ArchiverProxy.py [[--help | port] [HTTP-PROXY]]
An http proxy server which archives all your HTTP traffic.
http://logicerror.com/archiverProxy

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
 - Remove connection close hack, identify content length and use it as delimiter....
 - Identify if the host has changed and retain the connection if possible or initiate new connection
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

# Only save files with these content type prefixes (always lowercase)
ACCEPTED_CONTENT_TYPES = {'audio/mpeg' :'.mp3',
			  'video/x-flv':'.flv',
			  'video/mp4'  :'.mp4'
			  }

# Tagger rename pattern
# %A (artist), %a (album), %t (title), %n (track number),
# and %N (total number of tracks)

TAGGER_PATTERN = '%A - %t'

# debugging level,
#	0 = no debugging, only notices
#	1 = access and error debugging
#	2 = full debugging
#	3 = really full debugging
DEBUG_LEVEL = 3

SHOW_ERRORS = 1

# the address to bind the server to
ADDR_TO_BIND_TO = '127.0.0.1'

# put all the files from the same domain in the same directory ignoring their full path
DOMAIN_ONLY_DIRS = True

# Use date-stamped filenames or plain numbered ones?
ARCHIVE_FILE_NAMES = 'plain'
# ARCHIVE_FILE_NAMES = 'date'

# Start in archiving mode ?
ARCHIVE_ACTION_MODE = 'archive'
#ARCHIVE_ACTION_MODE = 'off'

ARCHIVE_ACTION_NAMES = {
	'archive':'Archiving',
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
		e = sys.stderr
	else:
		e = open('errors.txt','a')

	e.write(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())) + ' An error has occurred: \r\n')
	traceback.print_exception(sys.exc_type,sys.exc_value, sys.exc_traceback, file=e)
	e.write('\r\n')
	
	if e != sys.stderr:
		e.close()
		log('An error occurred, details are in errors.txt\n', v=0)
		
###############################################################################
# This is the section that is archiver-specific...
###############################################################################

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
	
# We have a single tagger object for tagging mp3s
tagger = Mp3Tagger();

###############################################################################

def re_exact_match(pattern, string):
	m = re.match(pattern, string)
	if m is None:
		return False
	return m.start() == 0 and m.end() == len(string)	
	
def keep_only_domain(webpath):
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
	

def archive_url2filename(url):
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
	if not os.path.isdir(dirname):
		while os.path.exists(dirname) and not os.path.isdir(dirname):
			dirname += '_'

		os.makedirs(dirname)
		log('Making directory: '+dirname+'\n', v=2)
	
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
		
	for i in ACCEPTED_CONTENT_TYPES.keys():
		if content_type.startswith(i):
			return True
	return False
		
def file_extension_for(content_type):
	if content_type is None:
		return ''
		
	for i in ACCEPTED_CONTENT_TYPES.keys():
		if content_type.startswith(i):
			return ACCEPTED_CONTENT_TYPES[i]
	return ''

###############################################################################

class Archiver(object):
	def __init__(self, sender):
		# (file, filename)
		self.archive = [None, None]
		#'init' ->'headers' -> 'body'|'noarchive' -> 'closed'
		self.status = 'init' 
		self.sender = sender
	
	def archive_headers(self, request, url, rawheaders):
		f, filename = self.archive
		self.status = 'headers'
		# Clean the request header:
		request = string.replace(request, '\r', '')
		request = string.replace(request, '\n', '')
		# Write out the URL/date header:
		first_line = request
		first_line += time.strftime(' %Y-%m-%dT%H:%M:%SZ',
				      time.gmtime(time.time()))
		first_line += '\r\n'

		self.content_type = extract_content_type(rawheaders)
		# Discard the file if it's not among the accepted content-types:
		if not content_type_accepted(self.content_type):
			log('Discarding ' + url +
				' -- content type not for archival\n', v=2)
			self.status = 'noarchive'
			return
		
		# Create a directory name based on the URL
		filename = archive_url2filename(url)
		
		# Store the headers to a file.
		log('Opening file: '+filename+'\n', v=2)
		open(filename, 'w').write(first_line + rawheaders)
		self.archive = [None, filename]
		
	
	def archive_connection(self, request, url, data):
		#print "ARCHIVE_CONNECTION" #TODO
		assert(self.status in ('headers', 'body', 'noarchive'))
		f, filename = self.archive
		
		# File should not be saved
		if self.status == 'noarchive':
			return
		log('+', v=0) #log progress
		if self.status == 'headers':
			# Open the data file
			filename = filename[:-len('.headers')]
			filename += file_extension_for(self.content_type)
			log('Switching to file: '+filename+' -- end of headers\n', v=2)
			f = open(filename, 'w')
			self.archive = [f, filename]
			self.status = 'body'
			
		f.write(data)
	
	def archive_close(self):
		del self.sender # break cycle
		if self.archive and self.archive[0] and self.archive[1]:
			f, filename = self.archive
			f.close()
			if tagger.is_mp3_file(filename):
				tagger.rename(filename, TAGGER_PATTERN)
		self.archive = None
		self.status = 'closed'

###############################################################################
class AsyncHTTPProxySender(asynchat.async_chat):
	def __init__(self, receiver, id, host, port):
		asynchat.async_chat.__init__(self)
		log('Initializing new AsyncHTTPProxySender\n', v=1)
		self.receiver = receiver
		self.id = id		
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port
		self.init_state()		
		try:
			self.connect( (host, port) )
		except socket.error, e:
			if e[0] is EWOULDBLOCK: log("@@DanC hack"); return
			log('(%d) XXX %s\n' % (self.id, e))
			self.receiver.sender_connection_error(e)
			self.close()
			return
		
	def init_state(self):
		log('S init_state\n', v=1)
		self.set_terminator('\r\n\r\n')
		self.found_terminator = self.end_of_headers
		# init => headers => body => closed
		self.status = 'init'
		self.buffer = StringIO()
		# Close any old archivers
		if hasattr(self, 'archiver') and self.archiver:
			self.archiver.archive_close()
		if ARCHIVE_ACTION_MODE != 'off':
			self.archiver = Archiver(self)
		else:
			self.archiver = None
	

	def handle_connect(self):
		log('(%d) S handle_connect\n' % self.id, 3)
		try:
			if sys.platform != 'win32':
				self.socket.recv(0)  # check for any socket errors during connect
			self.prepare_for_request()
			log('(%d) sender connected\n' % self.id, 2)
		except socket.error, e:
			log('(%d) OOO %s\n' % (self.id, e))
			if hasattr(self, 'receiver'):
				self.receiver.sender_connection_error(e)
			self.close()
			return


	def return_error(self, e):
		log('(%d) sender got socket error: %s\n', args=(self.id, e), v=2)
		if isinstance(e, socket.error) and type(e.args) == type(()) and len(e.args) == 2:
			e = e.args[1]  # get the error string only
		self.receiver.error(404, 'Error connecting to <em>%s</em> on port <em>%d</em>: <b>%s</b>' % (self.host, self.port, e), response=str(e))
		self.close()
	
	def end_of_headers(self):
		assert(self.status == 'headers')
		# some shorthands
		request = self.receiver.request
		url = self.receiver.url
		archiver = self.archiver
		# found end of headers
		headers = self.buffer.getvalue()
		del self.buffer
		log("----- GOT HEADERS: --------\n%s\n"%(headers) , v=3)
		self.content_length = self.parse_content_length(headers)
		log("PARSED Content-Length: %d\n"%(self.content_length), v=3)
		if self.content_length >= 0:
			self.set_terminator(self.content_length)
			self.found_terminator = self.end_of_content
		else:
			self.set_terminator(None)
		
		if archiver:
			archiver.archive_headers(request, url, headers)
		self.receiver.push(headers + '\r\n\r\n')
		self.status = 'body'
	
	def end_of_content(self):
		# after the body has been transmitted
		# reset the sender and the receiver to
		# handle any additional requests over the same connection
		assert(self.status == 'body')
		log("end_of_content\n", v=2)
		self.init_state()
		self.receiver.get_ready_for_new_request()
		
	def prepare_for_request(self):
		# Notify receiver that we are ready to receive the response headers
		self.receiver.sender_is_connected()
		self.status = 'headers'
		
	def collect_incoming_data(self, data):
		request = self.receiver.request
		url = self.receiver.url
		archiver = self.archiver

		if self.status == 'headers':
			self.buffer.write(data)
			return
		if self.status == 'body' and archiver:
			archiver.archive_connection(request, url, data)
		self.receiver.push(data)
		#
		if DEBUG_LEVEL >= 4:
			log('==> (s:%d) %s\n', args=(self.id, repr(data)), v=4)
		else:
			log('==> (s:%d) %d bytes\n', args=(self.id, len(data)), v=3)
			
	def handle_close(self):
		log('(%d) sender closing\n' % self.id, v=2)
		self.status = 'closed'
		if hasattr(self, 'receiver'):
			self.receiver.close_when_done()
			del self.receiver  # break circular reference
		if self.archiver:
			self.archiver.archive_close()
			self.archiver = None
		self.close()

	def parse_content_length(self, rawheaders):
		headers = rawheaders.lower().split()
		try:
			n = headers.index('content-length:')
			return int(headers[n+1])
		except:
			return -1
	
	def handle_error(self):
		self.archiver = None
		handle_error(self)
	
	def log(self, message):
		log('(%d) sender: %s\n', args=(self.id, message,), v=1)
	
	def log_info(self, message, type='info'):
		if __debug__ or type != 'info':
			log('%s: %s' % (type, message), v=0)
	
###############################################################################
class AsyncHTTPProxyReceiver(asynchat.async_chat):
	channel_counter = 0

	def __init__(self, server, (conn, addr)):
		# id used during log calls
		self.id = AsyncHTTPProxyReceiver.channel_counter
		AsyncHTTPProxyReceiver.channel_counter = (self.id + 1) % (2**32)
		asynchat.async_chat.__init__(self, conn)
		self.server = server
		self.host = None
		self.port = None
		self.get_ready_for_new_request()
		
	def get_ready_for_new_request(self):
		"""
		Resets the receiver to a state ready to receive an HTTP request.
		Called from the receiver constructor and called by the sender
		after finishing receiving a complete response (in case of keepalives.)
		"""
		if hasattr(self, 'rawheaders'):
			del self.rawheaders
		self.oldhost = self.host
		self.oldport = self.port
		# buffer up incoming data until the sender is ready to accept it
		self.buffer = StringIO()
		self.set_terminator('\n')
		# in the beginning there was GET...
		self.found_terminator = self.read_http_method
	
	def collect_incoming_data(self, data):
		# we are in buffering mode
		if self.buffer:
			self.buffer.write(data)
			return

		if DEBUG_LEVEL >= 4:
			log('<== (r:%d) %s\n', args=(self.id, repr(data)), v=4)
		else:
			log('<== (r:%d) %d bytes\n', args=(self.id, len(data)), v=3)
		self.sender.push(data)

	#### to be used as a found_terminator method
	def read_http_method(self):
		self.request = self.buffer.getvalue()
		self.buffer = StringIO()

		log('%s - %s\n', args=(time.ctime(time.time()), self.request), v=1)

		try:
			self.method, self.url, self.protocol = self.request.split()
			self.method = self.method.upper()
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
			return
		
		# all headers have been read, process them
		self.rawheaders.seek(0)
		self.mimeheaders = mimetools.Message(self.rawheaders)
		if (self.method == 'POST' or self.method == 'PUT') and not self.mimeheaders.has_key('content-length'):
			self.error(400, "Missing Content-Length for %s method" % self.method)
		self.length = int(self.mimeheaders.get('content-length', 0))
		del self.mimeheaders['accept-encoding']
		del self.mimeheaders['proxy-connection']

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
		# only if we are not already connected there (due to keep-alives)
		if (self.oldhost, self.oldport) == (self.host, self.port):
			log("Reusing sender\n", v=2)
			# Reuse the already existing sender
			self.sender.prepare_for_request()
		else:
			# Close the old sender, if one exists
			if hasattr(self, 'sender') and self.sender:
				log("Closing old sender (%d)\n"%(self.sender.id), v=2)
				self.sender.close()
			self.sender = AsyncHTTPProxySender(self, self.id, self.host, self.port)

		# send the request to the sender (this is its own method so that the sender can trigger
		# it again should its connection fail and it needs to redirect us to another site)
		self.push_request_to_sender()

	def push_request_to_sender(self):
		request = '%s %s %s\r\n%s\r\n' % (self.method, self.path, self.protocol, string.join(self.mimeheaders.headers, ''))

		if http_proxy:
			log('(%d) sending request to the next http proxy:\n' % self.id, v=2)
		else:
			log('(%d) sending request to server:%s\n' % (self.id, self.host), v=2)
		log(request, v=2)

		# send the request and headers on through to the next hop
		self.collect_incoming_data(request)

		# no more formatted IO, just pass any remaining data through
		self.set_terminator(None)
	
	def sender_is_connected(self):
		"""
		The sender calls this to tell us when it is ready for data
		"""
		log('(%d) R sender_is_connected()\n' % self.id, v=3)
		# sender gave is the OK, give it our buffered data and stop buffering
		buffered = self.buffer.getvalue()
		self.buffer = None
		self.collect_incoming_data(buffered)
	
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
		log("handle_accept\n", v=2)
		AsyncHTTPProxyReceiver(self, self.accept())
	
	def log(self, message):
		log('server: %s\n', args=(message,), v=1)

	def handle_error(self):
		handle_error()

if __name__ == '__main__':
	if len(sys.argv) >= 2 and sys.argv[1] == '--help':
		print __doc__ % {'PORT':PORT}
		print
		print "Version: " + __version__
		raise SystemExit

	# get the port if specified
	if len(sys.argv) >= 2:
		PORT = int(sys.argv[1])

	# display which proxy we're using
	http_proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
	if len(sys.argv) >= 3 :	# 3th param: the next-step HTTP proxy can specified here (overrides the environment variable)
		http_proxy = sys.argv[2]
	
	if http_proxy :
		log("Next hop proxy: %s\n" % http_proxy, v=1)
		scheme, netloc, path, params, query, fragment = urlparse.urlparse(http_proxy)
		# set host and port to the proxy
		if ':' in netloc:
			host, port = string.split(netloc, ':')
			port = string.atoi(port)
		else:
			host = netloc
			port = 80

	ps = AsyncHTTPProxyServer(PORT)
	log("Starting service...\n")	
	asyncore.loop()
