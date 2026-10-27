// Ordinary configuration: nothing here should be flagged.
public class SafeDemo {
    int passwordLength = 12;
    String PASSWORD_LABEL = "Enter your password";
    String API_KEY = System.getenv("API_KEY");
    String SECRET_KEY = "changeme";
    String serviceUrl = "https://example.com/api";
    String appName = "leakguard-demo";
}
