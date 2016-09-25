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
    using System.Collections.Generic;
    using System.Linq;
    using System.Web;
    using System.Web.Mvc;

    using EPi.Libraries.Security.Filters.Initialization;

    using EPiServer.Configuration;

    /// <summary>
    /// Class SecurityFilterProvider.
    /// </summary>
    /// <seealso cref="System.Web.Mvc.IFilterProvider" />
    /// <author>Jeroen Stemerdink</author>
    public class SecurityFilterProvider : IFilterProvider
    {
        /// <summary>
        /// Returns an enumerator that contains all the <see cref="T:System.Web.Mvc.IFilterProvider" /> instances in the service locator.
        /// </summary>
        /// <param name="controllerContext">The controller context.</param>
        /// <param name="actionDescriptor">The action descriptor.</param>
        /// <returns>The enumerator that contains all the <see cref="T:System.Web.Mvc.IFilterProvider" /> instances in the service locator.</returns>
        public IEnumerable<Filter> GetFilters(ControllerContext controllerContext, ActionDescriptor actionDescriptor)
        {
            List<Filter> filters = new List<Filter>();

            return IsOpenedInEditMode() ? Enumerable.Empty<Filter>() : FilterConfig.GetSecurityFilters();
        }

        private static bool IsOpenedInEditMode()
        {
            bool isInEditMode;

            try
            {
                isInEditMode =
                    HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)
                        .Contains(Settings.Instance.UIUrl.ToString().Replace("~", string.Empty));
            }
            catch (Exception)
            {
                return false;
            }

            return isInEditMode;
        }
    }
}