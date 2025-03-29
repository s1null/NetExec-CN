from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ldap_parser = parser.add_parser("ldap", help="使用LDAP协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ldap_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")
    ldap_parser.add_argument("--port", type=int, default=389, help="LDAP端口")

    dgroup = ldap_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="要认证的域")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    egroup = ldap_parser.add_argument_group("从远程域控制器获取哈希", "从Kerberos获取哈希的选项")
    egroup.add_argument("--asreproast", help="将AS_REP响应输出到文件以用hashcat破解")
    egroup.add_argument("--kerberoasting", help="将TGS票据输出到文件以用hashcat破解")

    vgroup = ldap_parser.add_argument_group("获取域中的有用信息", "获取域信息的选项")
    vgroup.add_argument("--base-dn", metavar="BASE_DN", dest="base_dn", type=str, default=None, help="搜索查询的基本DN")
    vgroup.add_argument("--query", nargs=2, help="使用自定义过滤器和属性查询LDAP")
    vgroup.add_argument("--find-delegation", action="store_true", help="查找Active Directory域中的委派关系（仅启用的帐户）")
    vgroup.add_argument("--trusted-for-delegation", action="store_true", help="获取具有TRUSTED_FOR_DELEGATION标志的用户和计算机列表")
    vgroup.add_argument("--password-not-required", action="store_true", help="获取具有PASSWD_NOTREQD标志的用户列表")
    vgroup.add_argument("--admin-count", action="store_true", help="获取adminCount=1的对象")
    vgroup.add_argument("--users", nargs="*", help="枚举域用户")
    vgroup.add_argument("--users-export", help="枚举域用户并导出到指定文件")
    vgroup.add_argument("--groups", nargs="?", const="", help="枚举域组，如果指定组则枚举其成员")
    vgroup.add_argument("--computers", action="store_true", help="枚举域计算机")
    vgroup.add_argument("--dc-list", action="store_true", help="枚举域控制器")
    vgroup.add_argument("--get-sid", action="store_true", help="获取域SID")
    vgroup.add_argument("--active-users", nargs="*", help="获取活动域用户账户")

    ggroup = ldap_parser.add_argument_group("从远程域控制器获取gmsa", "操作gmsa的选项")
    ggroup.add_argument("--gmsa", action="store_true", help="枚举GMSA密码")
    ggroup.add_argument("--gmsa-convert-id", help="获取特定gmsa或所有gmsa（如果未提供gmsa）的密钥名称")
    ggroup.add_argument("--gmsa-decrypt-lsa", help="从LSA解密gmsa加密值")

    bgroup = ldap_parser.add_argument_group("Bloodhound扫描", "使用Bloodhound的选项")
    bgroup.add_argument("--bloodhound", action="store_true", help="执行Bloodhound扫描")
    bgroup.add_argument("-c", "--collection", default="Default", help="要收集的信息。支持：Group（组）, LocalAdmin（本地管理员）, Session（会话）, Trusts（信任）, Default（默认）, DCOnly（仅域控制器）, DCOM, RDP, PSRemote, LoggedOn（已登录）, Container（容器）, ObjectProps（对象属性）, ACL, All（全部）。可以通过逗号分隔指定多个")

    return parser
