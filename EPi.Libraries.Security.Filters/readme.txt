In the EPiServer.Framework section of the web.config exclude the NWebsec assemblies form being scanned:

<episerver.framework>
    ...
    <scanAssembly forceBinFolderScan="true">
      <add assembly="*"/>
      <remove assembly="NWebsec" />
      <remove assembly="NWebsec.Core" />
      <remove assembly="NWebsec.Mvc" />
    </scanAssembly>
    ...
</episerver.framework>