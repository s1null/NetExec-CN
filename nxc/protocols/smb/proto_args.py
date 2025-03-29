from argparse import _StoreTrueAction
from nxc.helpers.args import DisplayDefaultsNotNone, DefaultTrackingAction


def proto_args(parser, parents):
    smb_parser = parser.add_parser("smb", help="使用SMB协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    smb_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")

    delegate_arg = smb_parser.add_argument("--delegate", action="store", help="使用S4U2Self + S4U2Proxy冒充用户")
    self_delegate_arg = smb_parser.add_argument("--self", dest="no_s4u2proxy", action=get_conditional_action(_StoreTrueAction), make_required=[], help="仅执行S4U2Self，不执行S4U2Proxy（与delegate一起使用）")

    dgroup = smb_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest="domain", type=str, help="要认证的域")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    smb_parser.add_argument("--port", type=int, default=445, help="SMB端口")
    smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="指定共享")
    smb_parser.add_argument("--smb-server-port", default="445", help="指定SMB服务器端口", type=int)
    smb_parser.add_argument("--no-smbv1", action="store_true", help="强制在连接中禁用SMBv1")
    smb_parser.add_argument("--gen-relay-list", metavar="OUTPUT_FILE", help="输出所有不需要SMB签名的主机到指定文件")
    smb_parser.add_argument("--smb-timeout", help="SMB连接超时", type=int, default=2)
    smb_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS认证", nargs="?", const="administrator")
    smb_parser.add_argument("--generate-hosts-file", type=str, help="从IP范围生成hosts文件")
    smb_parser.add_argument("--generate-krb5-file", type=str, help="从IP范围生成krb5文件")
    self_delegate_arg.make_required = [delegate_arg]

    cred_gathering_group = smb_parser.add_argument_group("凭据收集", "收集凭据的选项")
    cred_gathering_group.add_argument("--sam", choices={"regdump", "secdump"}, nargs="?", const="regdump", help="从目标系统转储SAM哈希")
    cred_gathering_group.add_argument("--lsa", choices={"regdump", "secdump"}, nargs="?", const="regdump", help="从目标系统转储LSA密钥")
    cred_gathering_group.add_argument("--ntds", choices={"vss", "drsuapi"}, nargs="?", const="drsuapi", help="使用指定方法从目标域控制器转储NTDS.dit")
    cred_gathering_group.add_argument("--dpapi", choices={"cookies", "nosystem"}, nargs="*", help="从目标系统转储DPAPI密钥，添加'cookies'可转储cookies，添加'nosystem'将不转储SYSTEM dpapi")
    cred_gathering_group.add_argument("--sccm", choices={"wmi", "disk"}, nargs="?", const="disk", help="从目标系统转储SCCM密钥")
    cred_gathering_group.add_argument("--mkfile", action="store", help="DPAPI选项。包含{GUID}:SHA1格式主密钥的文件")
    cred_gathering_group.add_argument("--pvk", action="store", help="DPAPI选项。包含域备份密钥的文件")
    cred_gathering_group.add_argument("--enabled", action="store_true", help="仅从域控制器转储启用的目标")
    cred_gathering_group.add_argument("--user", dest="userntds", type=str, help="从域控制器转储选定用户")

    mapping_enum_group = smb_parser.add_argument_group("映射/枚举", "映射/枚举的选项")
    mapping_enum_group.add_argument("--shares", action="store_true", help="枚举共享及访问权限")
    mapping_enum_group.add_argument("--dir", nargs="?", type=str, const="", help="列出路径内容（默认路径：'%(const)s'）")
    mapping_enum_group.add_argument("--interfaces", action="store_true", help="枚举网络接口")
    mapping_enum_group.add_argument("--no-write-check", action="store_true", help="跳过共享写入检查（当缺少删除权限时避免留下痕迹）")
    mapping_enum_group.add_argument("--filter-shares", nargs="+", help="按访问权限过滤共享，选项'read' 'write'或'read,write'")
    mapping_enum_group.add_argument("--smb-sessions", action="store_true", help="枚举活动SMB会话")
    mapping_enum_group.add_argument("--disks", action="store_true", help="枚举磁盘")
    mapping_enum_group.add_argument("--loggedon-users-filter", action="store", help="仅搜索特定用户，支持正则表达式")
    mapping_enum_group.add_argument("--loggedon-users", nargs="?", const="", help="枚举登录用户，如果指定用户则应用正则表达式过滤器")
    mapping_enum_group.add_argument("--users", nargs="*", metavar="USER", help="枚举域用户，如果指定用户则仅查询其信息")
    mapping_enum_group.add_argument("--users-export", help="枚举域用户并导出到指定文件")
    mapping_enum_group.add_argument("--groups", nargs="?", const="", metavar="GROUP", help="枚举域组，如果指定组则枚举其成员")
    mapping_enum_group.add_argument("--computers", nargs="?", const="", metavar="COMPUTER", help="枚举计算机用户")
    mapping_enum_group.add_argument("--local-groups", nargs="?", const="", metavar="GROUP", help="枚举本地组，如果指定组则枚举其成员")
    mapping_enum_group.add_argument("--pass-pol", action="store_true", help="转储密码策略")
    mapping_enum_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="通过暴力破解RID枚举用户")
    mapping_enum_group.add_argument("--qwinsta", action="store_true", help="枚举RDP连接")
    mapping_enum_group.add_argument("--tasklist", action="store_true", help="枚举运行进程")
    
    wmi_group = smb_parser.add_argument_group("WMI", "WMI查询选项")
    wmi_group.add_argument("--wmi", metavar="QUERY", type=str, help="执行指定的WMI查询")
    wmi_group.add_argument("--wmi-namespace", metavar="NAMESPACE", default="root\\cimv2", help="WMI命名空间")

    spidering_group = smb_parser.add_argument_group("爬取", "爬取共享的选项")
    spidering_group.add_argument("--spider", metavar="SHARE", type=str, help="要爬取的共享")
    spidering_group.add_argument("--spider-folder", metavar="FOLDER", default=".", type=str, help="要爬取的文件夹")
    spidering_group.add_argument("--content", action="store_true", help="启用文件内容搜索")
    spidering_group.add_argument("--exclude-dirs", type=str, metavar="DIR_LIST", default="", help="排除爬取的目录")
    spidering_group.add_argument("--depth", type=int, help="最大爬取递归深度")
    spidering_group.add_argument("--only-files", action="store_true", help="仅爬取文件")
    segroup = spidering_group.add_mutually_exclusive_group()
    segroup.add_argument("--pattern", nargs="+", help="在文件夹、文件名和文件内容中搜索的模式")
    segroup.add_argument("--regex", nargs="+", help="在文件夹、文件名和文件内容中搜索的正则表达式")

    files_group = smb_parser.add_argument_group("文件", "远程文件交互选项")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="将本地文件放入远程目标，例如：whoami.txt \\\\Windows\\\\Temp\\\\whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="获取远程文件，例如：\\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")
    files_group.add_argument("--append-host", action="store_true", help="将主机名附加到get-file文件名")

    cmd_exec_group = smb_parser.add_argument_group("命令执行", "执行命令的选项")
    cmd_exec_group.add_argument("--exec-method", choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default="wmiexec", help="执行命令的方法。在MSSQL模式下忽略", action=DefaultTrackingAction)
    cmd_exec_group.add_argument("--dcom-timeout", help="DCOM连接超时", type=int, default=5)
    cmd_exec_group.add_argument("--get-output-tries", help="atexec/smbexec/mmcexec尝试获取结果的次数", type=int, default=10)
    cmd_exec_group.add_argument("--codec", default="utf-8", help="设置目标输出使用的编码（codec）。如果检测到错误，在目标上运行chcp.com并使用https://docs.python.org/3/library/codecs.html#standard-encodings映射结果，然后使用--codec和相应的编码再次执行")
    cmd_exec_group.add_argument("--no-output", action="store_true", help="不获取命令输出")

    cmd_exec_method_group = cmd_exec_group.add_mutually_exclusive_group()
    cmd_exec_method_group.add_argument("-x", metavar="COMMAND", dest="execute", help="执行指定的CMD命令")
    cmd_exec_method_group.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="执行指定的PowerShell命令")

    posh_group = smb_parser.add_argument_group("PowerShell混淆", "PowerShell脚本混淆选项")
    posh_group.add_argument("--obfs", action="store_true", help="混淆PowerShell脚本")
    posh_group.add_argument("--amsi-bypass", nargs=1, metavar="FILE", help="包含自定义AMSI绕过的文件")
    posh_group.add_argument("--clear-obfscripts", action="store_true", help="清除所有缓存的混淆PowerShell脚本")
    posh_group.add_argument("--force-ps32", action="store_true", help="强制PowerShell命令在32位进程中运行（可能不适用于模块）")
    posh_group.add_argument("--no-encode", action="store_true", default=False, help="不对在目标上运行的PowerShell命令进行编码")

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction
