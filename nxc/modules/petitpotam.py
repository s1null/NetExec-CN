class NXCModule:
    name = "petitpotam"
    description = "[已移除] 检查DC是否易受PetitPotam漏洞攻击的模块，感谢@topotam"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        LISTENER            IP of your listener
        PIPE                Default PIPE (default: lsarpc)
        """
        self.listener = "127.0.0.1"
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]
        self.pipe = "lsarpc"
        if "PIPE" in module_options:
            self.pipe = module_options["PIPE"]

    def on_login(self, context, connection):
        context.log.fail('[REMOVED] This module moved to the new module "coerce_plus"')