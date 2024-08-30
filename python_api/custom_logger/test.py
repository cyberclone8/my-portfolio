from logger import CustomLogger, CodeTrigger, LogType
import os

# Example Usage:
if not os.path.exists('logs'):
    os.makedirs('logs')
if not os.path.exists('transferred_logs'):
    os.makedirs('transferred_logs')
logger = CustomLogger(storageName="StorageA", appId="APP1000PY", runTimeArgument="level2,ZRD", appVersion="1.0.0.4", 
                      projectId=1, serviceId="testapp", serverId="Server86", isServerEnvironment=True, userName="lance.lopez@izoologic.com")

# Writing log entries
def do_something():
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
    logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
    logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
    logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")


do_something()
logger.close()
