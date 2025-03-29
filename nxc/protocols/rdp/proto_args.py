from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    rdp_parser = parser.add_parser("rdp", help="使用RDP协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    rdp_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM哈希或包含NTLM哈希的文件")
    rdp_parser.add_argument("--port", type=int, default=3389, help="RDP端口")
    rdp_parser.add_argument("--rdp-timeout", type=int, default=5, help="RDP套接字连接超时")
    rdp_parser.add_argument("--nla-screenshot", action="store_true", help="如果NLA被禁用，截取RDP登录提示界面")

    dgroup = rdp_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="要认证的域")
    dgroup.add_argument("--local-auth", action="store_true", help="在每个目标上进行本地认证")

    egroup = rdp_parser.add_argument_group("截图", "远程桌面截图")
    egroup.add_argument("--screenshot", action="store_true", help="连接成功时截取RDP屏幕")
    egroup.add_argument("--screentime", type=int, default=10, help="等待桌面图像的时间")
    egroup.add_argument("--res", default="1024x768", help="分辨率，格式为宽x高")

    return parser
