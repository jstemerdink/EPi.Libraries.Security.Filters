# EPi.Libraries.Security.Filters
[![Build status](https://ci.appveyor.com/api/projects/status/y9bs8noiso1y0n2x/branch/master?svg=true)](https://ci.appveyor.com/project/jstemerdink/epi-libraries-security-filters/branch/master)
[![GitHub version](https://badge.fury.io/gh/jstemerdink%2FEPi.Libraries.Security.Filters.svg)](http://badge.fury.io/gh/jstemerdink%2FEPi.Libraries.Security.Filters)
[![Platform](https://img.shields.io/badge/platform-.NET 4.5-blue.svg?style=flat)](https://msdn.microsoft.com/en-us/library/w0x726c2%28v=vs.110%29.aspx)
[![Platform](https://img.shields.io/badge/EPiServer-%2010.0.0-orange.svg?style=flat)](http://world.episerver.com/cms/)
[![GitHub license](https://img.shields.io/badge/license-MIT%20license-blue.svg?style=flat)](LICENSE)

Administer security headers through EPiServer and use [NWebsec](https://github.com/NWebsec/NWebsec/wiki) to add them to your response.

Don't forget to exclude the NWebsec dll's from assembly scanning, as it will throw an error.

```
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
```

> *Powered by ReSharper*

> [![image](http://resources.jetbrains.com/assets/media/open-graph/jetbrains_250x250.png)](http://jetbrains.com)