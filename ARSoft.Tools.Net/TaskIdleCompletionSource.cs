#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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

namespace ARSoft.Tools.Net;

internal class TaskIdleCompletionSource : IDisposable
{
	private readonly TaskCompletionSource _tcs = new();
	private readonly Timer _timer;
	private TimeSpan _timeout;

	public TaskIdleCompletionSource(TimeSpan idleTimeout)
	{
		_timer = new Timer(TimerCallback);
		_timeout = idleTimeout;
	}

	public Task Task => _tcs.Task;

	public bool SetIdleTimeout(TimeSpan newIdleTimeout)
	{
		lock (_tcs)
		{
			if (_tcs.Task.IsCompleted)
				return false;

			_timeout = newIdleTimeout;
			_timer.Change(_timeout, Timeout.InfiniteTimeSpan);
			return true;
		}
	}

	public void Pause()
	{
		lock (_tcs)
		{
			if (_tcs.Task.IsCompleted)
				return;

			_timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
		}
	}

	public void Start()
	{
		lock (_tcs)
		{
			if (_tcs.Task.IsCompleted)
				return;

			_timer.Change(_timeout, Timeout.InfiniteTimeSpan);
		}
	}

	private void TimerCallback(object? state)
	{
		lock (_tcs)
		{
			_tcs.TrySetResult();
			_timer.Dispose();
		}
	}

	public void Dispose()
	{
		lock (_tcs)
		{
			if (_tcs.Task.IsCompleted)
				return;
		}

		_timer.Dispose();
	}
}