from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    vnc_parser = parser.add_parser("vnc", help="使用VNC协议攻击目标", parents=parents, formatter_class=DisplayDefaultsNotNone)
    vnc_parser.add_argument("--port", type=int, default=5900, help="VNC端口")
    vnc_parser.add_argument("--vnc-sleep", type=int, default=5, help="VNC套接字连接时休眠以避免速率限制")

    egroup = vnc_parser.add_argument_group("截图", "VNC服务器")
    egroup.add_argument("--screenshot", action="store_true", help="连接成功时截取VNC屏幕")
    egroup.add_argument("--screentime", type=int, default=5, help="等待桌面图像的时间")

    return parser
