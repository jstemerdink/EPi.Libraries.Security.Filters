// Copyright © 2016 Jeroen Stemerdink.
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
namespace EPi.Libraries.Security.Filters.Models
{
    using System;

    using EPiServer.Data.Dynamic;

    /// <summary>
    /// Class SecurityFilterConfiguration.
    /// </summary>
    [EPiServerDataStore(AutomaticallyRemapStore = true)]
    public class SecurityFilterConfiguration
    {
        /// <summary>
        /// Deny - Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser to
        /// display the page when it is loaded in an iframe - but only if the iframe is from the same origin as the page.
        /// </summary>
        public const string Deny = "Deny";

        /// <summary>
        /// Disabled - Specifies that the X-Frame-Options header should not be set in the HTTP response.
        /// </summary>
        public const string Disabled = "Disabled";

        /// <summary>
        /// SameOrigin - Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser
        /// to not display the page when it is loaded in an iframe.
        /// </summary>
        public const string SameOrigin = "SameOrigin";

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow base URI from same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow base URI from same domain]; otherwise, <c>false</c>.</value>
        public bool AllowBaseUriFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow loading web workers or embed frames source from same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow loading web workers or embed frames source from same domain]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     This directive restricts from where the protected resource can load web workers or embed frames.
        ///     This was introduced in CSP 2.0 to replace frame-src. frame-src should still be used for older browsers.
        /// </remarks>
        public bool AllowChildSrcFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow all AJAX and Web Sockets calls from the same domain].
        /// </summary>
        /// <value><c>true</c> if [allow all AJAX and Web Sockets calls from the same domain]; otherwise, <c>false</c>.</value>
        public bool AllowConnectionsFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [allow loadingfonts from same domain].
        /// </summary>
        /// <value><c>true</c> if [allow loading fonts from same domain]; otherwise, <c>false</c>.</value>
        public bool AllowFontsFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow forms to post back to the same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow forms to post back to the same domain]; otherwise, <c>false</c>.</value>
        public bool AllowFormActionToSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow frame, iframe, object, embed or applet's from the same domain].
        /// </summary>
        /// <value>
        ///     <c>true</c> if to [allow frame, iframe, object, embed or applet's from the same domain]; otherwise, <c>false</c>
        ///     .
        /// </value>
        /// <remarks>This directive restricts from where the protected resource can embed frame, iframe, object, embed or applet's.</remarks>
        public bool AllowFrameAncestorsFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow iframes from the same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow iframes from the same domain]; otherwise, <c>false</c>.</value>
        /// <remarks>Allow iFrames from the same domain.</remarks>
        public bool AllowFramesFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow images from same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow images from same domain]; otherwise, <c>false</c>.</value>
        public bool AllowImagesFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow audio and video from the same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow audio and video from the same domain]; otherwise, <c>false</c>.</value>
        public bool AllowMediaFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow plugins from same domain].
        /// </summary>
        /// <value><c>true</c> if to [allow plugins from same domain]; otherwise, <c>false</c>.</value>
        public bool AllowPluginsFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [allow scripts from same domain].
        /// </summary>
        /// <value><c>true</c> if [allow scripts from same domain]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     This directive restricts which scripts the protected resource can execute.
        ///     The directive also controls other resources, such as XSLT style sheets, which can cause the user agent to execute
        ///     script.
        /// </remarks>
        public bool AllowScriptsFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [allow styles from same domain].
        /// </summary>
        /// <value><c>true</c> if [allow styles from same domain]; otherwise, <c>false</c>.</value>
        public bool AllowStylesFromSameDomain { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [allow unsafe eval].
        /// </summary>
        /// <value><c>true</c> if [allow unsafe eval]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     Allow the use of the eval() method to create code from strings. This is unsafe and can open your site up to
        ///     XSS vulnerabilities.
        /// </remarks>
        public bool AllowUnsafeEval { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [allow unsafe inline].
        /// </summary>
        /// <value><c>true</c> if [allow unsafe inline]; otherwise, <c>false</c>.</value>
        /// <remarks>Allow inline JavaScript, this is unsafe and can open your site up to XSS vulnerabilities.</remarks>
        public bool AllowUnsafeInline { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [allow unsafe inline styles].
        /// </summary>
        /// <value><c>true</c> if to [allow unsafe inline styles]; otherwise, <c>false</c>.</value>
        public bool AllowUnsafeInlineStyles { get; set; }

        /// <summary>
        ///     Gets or sets the custom base URI sources.
        /// </summary>
        /// <value>The custom base URI sources.</value>
        /// <remarks>Allow base URL's from example.com.</remarks>
        public string CustomBaseUriSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom child sources.
        /// </summary>
        /// <value>The custom child sources.</value>
        /// <remarks>Allow web workers or embed frames from example.com.</remarks>
        public string CustomChildSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom connection sources.
        /// </summary>
        /// <value>The custom connection sources.</value>
        /// <remarks>
        ///     Allow AJAX and Web Sockets to example.com.
        /// </remarks>
        public string CustomConnectionSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom font sources.
        /// </summary>
        /// <value>The custom font sources.</value>
        /// <remarks>Allow fonts from example.com</remarks>
        public string CustomFontSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom form action sources.
        /// </summary>
        /// <value>The custom form action sources.</value>
        /// <remarks>Allow forms to post back to example.com.</remarks>
        public string CustomFormActionSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom frame ancestors sources.
        /// </summary>
        /// <value>The custom frame ancestors sources.</value>
        /// <remarks>Allow frame, iframe, object, embed or applet's from example.com.</remarks>
        public string CustomFrameAncestorsSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom frame sources.
        /// </summary>
        /// <value>The custom frame sources.</value>
        /// <remarks>
        ///     This directive restricts from where the protected resource can embed frames.
        ///     This is now deprecated in favour of child-src but should still be used for older browsers.
        /// </remarks>
        public string CustomFrameSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom image sources.
        /// </summary>
        /// <value>The custom image sources.</value>
        /// <remarks>Allow images from example.com.</remarks>
        public string CustomImageSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom media sources.
        /// </summary>
        /// <value>The custom media sources.</value>
        /// <remarks>Allow audio and video from example.com.</remarks>
        public string CustomMediaSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom plugin sources.
        /// </summary>
        /// <value>The custom plugin sources.</value>
        /// <remarks>Allow plugins from example.com.</remarks>
        public string CustomPluginSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom script sources.
        /// </summary>
        /// <value>The custom script sources.</value>
        /// <remarks>Allow scripts from CDN's.</remarks>
        public string CustomScriptSources { get; set; }

        /// <summary>
        ///     Gets or sets the custom style sources.
        /// </summary>
        /// <value>The custom style sources.</value>
        /// <remarks>Allow CSS from example.com.</remarks>
        public string CustomStyleSources { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [disable version headers].
        /// </summary>
        /// <value><c>true</c> if [disable version headers]; otherwise, <c>false</c>.</value>
        public bool DisableVersionHeaders { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [enable Content-Security-Policy].
        /// </summary>
        /// <value><c>true</c> if to [enable Content-Security-Policy]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     Add the Content-Security-Policy HTTP header to enable Content-Security-Policy.
        /// </remarks>
        public bool EnableContentSecurityPolicy { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [enable X-Content-Type-Options].
        /// </summary>
        /// <value><c>true</c> if to [enable X-Content-Type-Options]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     Adds the X-Content-Type-Options HTTP header. Stop IE9 and below from sniffing files and overriding the Content-Type
        ///     header (MIME type).
        /// </remarks>
        public bool EnableXContentTypeOptions { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [enable X-Download-Options].
        /// </summary>
        /// <value><c>true</c> if to [enable X-Download-Options]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     Adds the X-Download-Options HTTP header. When users save the page, stops them from opening it and forces a save and
        ///     manual open.
        /// </remarks>
        public bool EnableXDownloadOptions { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to [enable X-Frame-Options].
        /// </summary>
        /// <value><c>true</c> if to [enable X-Frame-Options]; otherwise, <c>false</c>.</value>
        /// <remarks>
        ///     Adds the X-Frame-Options HTTP header. Stop clickjacking by stopping the page from opening in an iframe or only
        ///     allowing it from the same origin.
        /// </remarks>
        public bool EnableXFrameOptions { get; set; }

        /// <summary>
        ///     Gets or sets the data entity ID.
        /// </summary>
        /// <value>
        ///     The entity ID.
        /// </value>
        public Guid Id { get; set; }

        /// <summary>
        ///     Gets or sets the X-Frame-Options policy.
        /// </summary>
        /// <value>The X-Frame-Options policy.</value>
        /// <remarks>
        ///     Deny - Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser to
        ///     display the page when it is loaded in an iframe - but only if the iframe is from the same origin as the page.
        ///     SameOrigin - Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser
        ///     to not display the page when it is loaded in an iframe.
        ///     Disabled - Specifies that the X-Frame-Options header should not be set in the HTTP response.
        /// </remarks>
        public string XFrameOptionsPolicy { get; set; }
    }
}