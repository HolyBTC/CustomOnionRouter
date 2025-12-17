using System.Net.ServerSentEvents;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace OnionRouter.Server.Api.Controllers;

[Route("api/event")]
[ApiController]
public class EventController
{
    [HttpGet("live-updates")]
    public ServerSentEventsResult<Test> GetLiveUpdates(CancellationToken cancellationToken)
    {
        return TypedResults.ServerSentEvents(GetLiveUpdatesAsync(cancellationToken));
    }

    private async IAsyncEnumerable<SseItem<Test>> GetLiveUpdatesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(1000);
            yield return new SseItem<Test>(new Test { Name = "Random name" }, "event-type")
            {
                EventId = Guid.NewGuid().ToString(),
                ReconnectionInterval = TimeSpan.FromMinutes(1),
            };
        }
    }
}


public class Test
{
    public string Name { get; set; }
}