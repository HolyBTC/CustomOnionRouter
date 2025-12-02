namespace OnionRouter.Helpers;

public static class ByteArrayExtension
{
    extension(byte[]? arr)
    {
        public bool IsNullOrEmpty()
        {
            return arr is null || arr.Length == 0;
        }
    }
}