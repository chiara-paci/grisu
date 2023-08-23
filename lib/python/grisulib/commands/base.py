import traceback

def print_tree(elem,indent=""):
    if elem.attrib:
        print(indent,elem.tag,elem.attrib)
    else:
        print(indent,elem.tag,elem.attrib)
    if (elem.text is not None) and elem.text.strip():
        print(indent+"    ",elem.text.strip())
    for ch in elem:
        print_tree(ch,indent+"    ")

class CommandError(Exception):
    def __init__(self,ret_code,error,output):
        self.ret_code=ret_code
        self.error=error
        self.output=output

    def __str__(self):
        return "%d %s" % (self.ret_code,self.error)

class CommandWrapError(Exception):
    def __init__(self,name,inner,ret_code=-1,output='',error=''):
        self.name=name
        self.inner=inner
        self.ret_code=ret_code
        self.output=output
        if error:
            self.error=error+'\n'
        else:
            self.error=''
        tb_exc=traceback.TracebackException.from_exception(inner)
        self.error+=''.join(tb_exc.format())

    def __str__(self):
        return str(self.inner)

    def __repr__(self):
        return self.inner.__repr__()

