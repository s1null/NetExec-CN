from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    mssql_parser = parser.add_parser("mssql", help="使用MSSQL协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    mssql_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")
    mssql_parser.add_argument("--port", default=1433, type=int, metavar="PORT", help="MSSQL端口")
    mssql_parser.add_argument("--mssql-timeout", help="SQL服务器连接超时", type=int, default=5)
    mssql_parser.add_argument("-q", "--query", dest="mssql_query", metavar="QUERY", type=str, help="对MSSQL数据库执行指定查询")

    dgroup = mssql_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, help="域名")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    cgroup = mssql_parser.add_argument_group("命令执行", "执行命令的选项")
    cgroup.add_argument("--no-output", action="store_true", help="不获取命令输出")
    xgroup = cgroup.add_mutually_exclusive_group()
    xgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="执行指定的命令")
    xgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="执行指定的PowerShell命令")

    psgroup = mssql_parser.add_argument_group("PowerShell选项", "PowerShell执行选项")
    psgroup.add_argument("--force-ps32", action="store_true", default=False, help="通过作业在32位进程中运行PowerShell命令；警告：取决于作业快速完成，所以可能需要增加超时时间")
    psgroup.add_argument("--obfs", action="store_true", default=False, help="混淆在目标上运行的PowerShell；警告：Defender几乎肯定会对此触发报警")
    psgroup.add_argument("--amsi-bypass", nargs=1, metavar="FILE", type=str, help="包含自定义AMSI绕过的文件")
    psgroup.add_argument("--clear-obfscripts", action="store_true", help="清除所有缓存的混淆PowerShell脚本")
    psgroup.add_argument("--no-encode", action="store_true", default=False, help="不对在目标上运行的PowerShell命令进行编码")

    tgroup = mssql_parser.add_argument_group("文件", "上传和获取远程文件的选项")
    tgroup.add_argument("--put-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="将本地文件放入远程目标，例如：whoami.txt C:\\\\Windows\\\\Temp\\\\whoami.txt")
    tgroup.add_argument("--get-file", nargs=2, metavar=("SRC_FILE", "DEST_FILE"), help="获取远程文件，例如：C:\\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")

    mapping_enum_group = mssql_parser.add_argument_group("映射/枚举", "映射/枚举的选项")
    mapping_enum_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="通过暴力破解RID枚举用户")
    return parser