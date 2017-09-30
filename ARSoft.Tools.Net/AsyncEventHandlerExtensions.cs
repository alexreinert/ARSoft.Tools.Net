#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System;
using System.Linq;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net
{
	internal static class AsyncEventHandlerExtensions
	{
		public static Task RaiseAsync<T>(this AsyncEventHandler<T> eventHandler, object sender, T eventArgs)
			where T : EventArgs
		{
			if (eventHandler == null)
				return Task.FromResult(false);

			return Task.WhenAll(eventHandler.GetInvocationList().Cast<AsyncEventHandler<T>>().Select(x => x.Invoke(sender, eventArgs)));
		}
	}
}