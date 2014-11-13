

from time import *
import datetime


class Logger:
    def __init__(self,filename,iface):
        date = str(datetime.datetime.today()).split(" ")[0]
        self.logFile = open("log/"+date+".log","wa")
        self.iface = iface


    def writeLog(self,src,content,comment):
        try:
            now = time()
            ctime = localtime(now)
            log = "\t" + content + " from " + src + " *** " + comment + "\n"
        except KeyboardInterrupt:
            self.logFile.close()

    def writeDetails(self,atktype,src,srcm,target,dstm,comment):
        try:
            log = "\n["+atktype+"]\n"
            log += "\tTime   :\t"+ str(datetime.datetime.today().replace(microsecond=0))+"\n"
            log += "\tFrom   :\t"+ src+ "\t(" + srcm + ")\n" 
            log += "\tTo     :\t"+ target +"\t(" + dstm + ")\n"
            log +="\tDesc   :\t"+ comment + "\n"
            self.logFile.write(log)
            print log
        except KeyboardInterrupt:
            self.logFile.close()
    def writeRea(self,content):
        try:
            self.logFile.writelines(content+"\n")
        except KeyboardInterrupt:
            self.logFile.close()
    def cleanLog(self):
      return


