from _pyreport import *


#Compatibility with report package:

import os

def createAlertSignature(component, hashmarkername, hashvalue, summary, alertSignature):

    SYSTEM_RELEASE_PATHS = ["/etc/system-release","/etc/redhat-release"]
    ####SYSTEM_RELEASE_DEPS = ["system-release", "redhat-release"]

    _hardcoded_default_product = ""
    _hardcoded_default_version = ""

    ####def getProduct_fromPRODUCT():
    ####    try:
    ####        import product
    ####        return product.productName
    ####    except:
    ####        return ""

    ####def getVersion_fromPRODUCT():
    ####    try:
    ####        import product
    ####        return product.productVersion
    ####    except:
    ####        return ""

    ####def getProduct_fromRPM():
    ####    try:
    ####        import rpm
    ####        ts = rpm.TransactionSet()
    ####        for each_dep in SYSTEM_RELEASE_DEPS:
    ####            mi = ts.dbMatch('provides', each_dep)
    ####            for h in mi:
    ####                if h['name']:
    ####                    return h['name'].split("-")[0].capitalize()
    ####
    ####        return ""
    ####    except:
    ####        return ""

    ####def getVersion_fromRPM():
    ####    try:
    ####        import rpm
    ####        ts = rpm.TransactionSet()
    ####        for each_dep in SYSTEM_RELEASE_DEPS:
    ####            mi = ts.dbMatch('provides', each_dep)
    ####            for h in mi:
    ####                if h['version']:
    ####                    return str(h['version'])
    ####        return ""
    ####    except:
    ####        return ""

    def getProduct_fromFILE():
        for each_path in SYSTEM_RELEASE_PATHS:
            try:
                file = open(each_path, "r")
                content = file.read()
                if content.startswith("Red Hat Enterprise Linux"):
                    return "Red Hat Enterprise Linux"
                if content.startswith("Fedora"):
                    return "Fedora"
                i = content.find(" release")
                if i > -1:
                    return content[0:i]
            except:
                pass
        return ""

    def getVersion_fromFILE():
        for each_path in SYSTEM_RELEASE_PATHS:
            try:
                file = open(each_path, "r")
                content = file.read()
                if content.find("Rawhide") > -1:
                    return "rawhide"
                clist = content.split(" ")
                i = clist.index("release")
                return clist[i+1]
            except:
                pass
        return ""

    def getProduct():
        ####product = getProduct_fromPRODUCT()
        ####if product:
        ####    return product
        product = getProduct_fromFILE()
        if product:
            return product
        ####product = getProduct_fromRPM()
        ####if product:
        ####    return product
        return _hardcoded_default_product

    def getVersion():
        ####version = getVersion_fromPRODUCT()
        ####if version:
        ####    return version
        version = getVersion_fromFILE()
        if version:
            return version
        ####version = getVersion_fromRPM()
        ####if version:
        ####    return version
        return _hardcoded_default_version

    cd = problem_data()
    cd.add("component", component)
    cd.add("hashmarkername", hashmarkername)
    cd.add("localhash", hashvalue)
    cd.add("summary", summary)
    cd.add("description", alertSignature)
    cd.add("product", getProduct())
    cd.add("version", getVersion())
    return cd

def report(cd, io_unused):
    #dd = cd.create_dump_dir()
    #dir_name = dd.name
    #dd.close()
    #r = os.spawnlp(P_WAIT, "abrt-handle-crashdump", "abrt-handle-crashdump", "-d", dirname, "-e" , "report");
    ### Silmpler alternative:
    state = run_event_state()
    #state.logging_callback = logfunc
    r = state.run_event_on_problem_data(cd, "report")
    return r
