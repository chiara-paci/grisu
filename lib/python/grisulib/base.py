import urllib.parse


class RegisterCls(object):
    def __init__(self):
        self.sections={"-": []}
        self.objects={}

    @property
    def choices(self):
        ret=[]
        for c in self.sections["-"]:
            ret.append( c )
        for sec in self.sections:
            if sec=="-": continue
            ret.append( (sec,None,self.sections[sec]) )
        return ret

    def register(self,cmd_cls,section="-"):
        if not section in self.sections: 
            self.sections[section]=[]
        self.sections[section].append((cmd_cls.flags,cmd_cls.dest,cmd_cls.name)) 
        self.sections[section].sort()
        self.objects[cmd_cls.dest]=cmd_cls()

    def get_commands(self,options):
        ret=[]
        for k in options:
            if k in self.objects and options[k]:
                ret.append(self.objects[k])
        return ret

class TestRegisterCls(RegisterCls): pass

TestRegister=TestRegisterCls()

class AssertionRegisterCls(RegisterCls): pass

AssertionRegister=AssertionRegisterCls()

class TargetError(Exception): pass

class Target(object):
    def __init__(self,hostadr,port=None,url=None,proxychains=None,secondary_ip=None,use_secondary=False):
        self.hostadr=hostadr
        self.port=port
        self.url=url
        self.proxychains=proxychains
        self.secondary_ip=secondary_ip 
        self.use_secondary=use_secondary

    def __str__(self):
        return "%s:%s" % (self.hostadr,self.port)

    def __serialize__(self):
        ret={
            "hostadr": self.hostadr,
        }

        for k in ["port","url","proxychains",
                  "secondary_ip","use_secondary"]:
            if self.__getattribute__(k) is not None:
                ret[k]=self.__getattribute__(k)

        if "url" in ret:
            ret["servername"]=self.servername

        return ret

    @staticmethod
    def from_options(options):
        hostadr=options["hostadr"]
        kwargs={}
        for k in ["port","url"]:
            if k in options and options[k] is not None:
                kwargs[k]=options[k]
        return Target(hostadr,**kwargs)

    def get_ip(self,force_secondary=False):
        if self.secondary_ip is None: return self.hostadr
        if force_secondary:
            return self.secondary_ip
        if self.use_secondary:
            return self.secondary_ip
        return self.hostadr

    @property
    def servername(self):
        if self.url is None: return None
        if '://' in self.url:
            u=urllib.parse.urlparse(self.url)
        else:
            u=urllib.parse.urlparse("https://"+self.url)
        if u.hostname is not None:
            return u.hostname
        raise TargetError('wrong url: %s' % self.url)
        
