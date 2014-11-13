import ConfigParser
import io


class v6Sig:
  def __init__(self,sigFile):
    cfgFile = open("conf/"+sigFile,"r")
    cfgContent = cfgFile.read()
    self.config = ConfigParser.RawConfigParser(allow_no_value=True)
    self.config.readfp(io.BytesIO(cfgContent))

    self.raLimit = int(self.config.get('config',"raLimit"))
    self.routerLifetime = int(self.config.get('config',"routerLifetime"))
    self.naLimit = int(self.config.get('config',"naLimit"))
    self.icmpLimit = int(self.config.get('config',"icmpLimit"))
    self.limitRate = int(self.config.get('config',"limitRate"))

    self.macFile = self.config.get("generic","manuFile")
