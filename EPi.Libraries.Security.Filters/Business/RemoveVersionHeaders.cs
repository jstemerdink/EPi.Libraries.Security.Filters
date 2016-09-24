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
namespace EPi.Libraries.Security.Filters.Business
{
    using System;
    using System.Web.Mvc;

    using EPiServer.Logging;

    /// <summary>
    /// Class RemoveVersionHeaders.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class RemoveVersionHeaders : ActionFilterAttribute
    {
        private readonly ILogger log = LogManager.GetLogger(typeof(RemoveVersionHeaders));

        /// <summary>
        /// Called by the ASP.NET MVC framework after the action method executes.
        /// </summary>
        /// <param name="filterContext">The filter context.</param>
        public override void OnActionExecuted(ActionExecutedContext filterContext)
        {
            if (filterContext == null)
            {
                return;
            }

            try
            {
                filterContext.HttpContext.Response.Headers.Remove("X-Powered-By");
                filterContext.HttpContext.Response.Headers.Remove("X-AspNet-Version");
                filterContext.HttpContext.Response.Headers.Remove("X-AspNetMvc-Version");
                filterContext.HttpContext.Response.Headers.Remove("Server");
            }
            catch (NotImplementedException notImplementedException)
            {
                this.log.Debug(notImplementedException.Message);
            }
            catch (NotSupportedException notSupportedException)
            {
                this.log.Debug(notSupportedException.Message);
            }

            base.OnActionExecuted(filterContext);
        }
    }
}