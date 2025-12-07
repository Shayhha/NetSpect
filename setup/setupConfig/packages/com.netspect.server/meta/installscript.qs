function Component() {}

Component.prototype.createOperations = function() {
    component.createOperations();

    component.addOperation("CreateShortcut",
        "@TargetDir@/server/NetSpectServer.exe",
        "@DesktopDir@/NetSpect™ Server.lnk",
        "workingDirectory=@TargetDir@/server",
        "iconPath=@TargetDir@/server/_internal/app/static/NetSpectIconTransparent.ico",
        "description=NetSpect™ IDS Server"
    );

    component.addOperation("CreateShortcut",
        "@TargetDir@/server/NetSpectServer.exe",
        "@StartMenuDir@/NetSpect/NetSpect™ Server.lnk",
        "workingDirectory=@TargetDir@/server",
        "iconPath=@TargetDir@/server/_internal/app/static/NetSpectIconTransparent.ico",
        "description=NetSpect™ IDS Server"
    );
}