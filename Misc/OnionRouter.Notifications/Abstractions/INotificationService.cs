namespace OnionRouter.Notifications.Abstractions;

public interface INotificationService
{
    void Register(string id);

    void Unregister(string id);

    Task SendNotificationAsync<T>(T data, CancellationToken cancellationToken = default) where T : class;
}