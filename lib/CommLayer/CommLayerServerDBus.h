#include "CommLayerServer.h"

#include <dbus-c++/dbus.h>
#include <dbus-c++/glib-integration.h>
#include "DBusServerProxy.h"
#include <iostream>

class CCommLayerServerDBus
: public CCommLayerServer,
  public CDBusServer_adaptor,
  public DBus::IntrospectableAdaptor,
  public DBus::ObjectAdaptor
{
    private:
        DBus::Connection *m_pConn;
        DBus::Glib::BusDispatcher *m_pDispatcher;
        static DBus::Connection *init_dbus(CCommLayerServerDBus *self);
    public:
        CCommLayerServerDBus(CMiddleWare *m_pMW);
        virtual ~CCommLayerServerDBus();

        virtual vector_crash_infos_t GetCrashInfos(const std::string &pDBusSender);
        virtual dbus_vector_map_crash_infos_t GetCrashInfosMap(const std::string &pDBusSender);
        virtual map_crash_report_t CreateReport(const std::string &pUUID,const std::string &pDBusSender);
        virtual bool Report(map_crash_report_t pReport);
        virtual bool DeleteDebugDump(const std::string& pUUID, const std::string& pDBusSender);
        
        void Crash(const std::string& arg1);
        void AnalyzeComplete(map_crash_report_t arg1);
        void Error(const std::string& arg1);
};
