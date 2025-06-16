function Component() {}

Component.prototype.createOperations = function() {
    component.createOperations();

    component.addOperation("CreateShortcut",
        "@TargetDir@/NetSpect.exe",
        "@DesktopDir@/NetSpect™.lnk",
        "workingDirectory=@TargetDir@",
        "iconPath=@TargetDir@/_internal/interface/Icons/NetSpectIconTransparent.ico",
        "description=NetSpect™ IDS"
    );
}

