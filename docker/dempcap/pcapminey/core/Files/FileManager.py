# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

import sys
sys.path.append('../..')

import os
import core.Utils as Utils
from Queue import Queue
from threading import Thread

class FileManager(Thread):
    def __init__(self, outputdir):
        Thread.__init__(self)
        self.setName('FileManager thread')
        self.daemon = True

        self.files = Queue()
        self.outputdir = outputdir
	self.filenamelist = []
        self.stop = False
        self.start()

    def addFile(self, file):
        self.files.put(file)

    def exit(self):
        self.files.join()
        self.stop = True
        self.files.put(None)
        self.join()

    def run(self):
        while not self.stop or not self.files.empty():
            file = self.files.get()

            if not file:
                self.files.task_done()
                continue

            newtimestamp = file.timestamp.replace(" ", "_")
            filenamepath = "%s_%ss_%s_%s_%s_" % (self.outputdir, file.type, file.source, file.destination, newtimestamp)
            path = "%s/%ss/%s_%s/%s/" % (self.outputdir, file.type, file.source, file.destination, newtimestamp)
            path2 = "%s/" % (self.outputdir)
            if not os.path.exists(path2):
                os.makedirs(path2)

            number = 1
            filename = '%s_%d.%s' % (file.name, number, file.fileEnding)
            #while os.path.exists(path + filename):
            while os.path.exists(path2 + filename):
                number += 1
                filename = '%s_%d.%s' % (file.name, number, file.fileEnding)

            filename = filenamepath + filename.rstrip('.')
            #with open(path + filename, 'wb') as outfile:
            with open(path2+filename, 'wb') as outfile:
                outfile.write(file.data)
		self.filenamelist.append(filename)
                #Utils.printl("Wrote file: %s%s" % (path2, filename))

            self.files.task_done()
