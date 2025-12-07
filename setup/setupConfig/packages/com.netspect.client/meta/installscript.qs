function Component() {}

Component.prototype.createOperations = function() {
    component.createOperations();

    component.addOperation("CreateShortcut",
        "@TargetDir@/client/NetSpect.exe",
        "@DesktopDir@/NetSpect™.lnk",
        "workingDirectory=@TargetDir@/client",
        "iconPath=@TargetDir@/client/_internal/interface/Icons/NetSpectIconTransparent.ico",
        "description=NetSpect™ IDS"
    );

    component.addOperation("CreateShortcut",
        "@TargetDir@/client/NetSpect.exe",
        "@StartMenuDir@/NetSpect/NetSpect™.lnk",
        "workingDirectory=@TargetDir@/client",
        "iconPath=@TargetDir@/client/_internal/interface/Icons/NetSpectIconTransparent.ico",
        "description=NetSpect™ IDS"
    );
}