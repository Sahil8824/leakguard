// FICTIONAL demo data only. None of these are real credentials.
public class VulnerableDemo {
    private static final int PORT = 8080;
    String API_KEY = "demo_secret_123456";
    String PASSWORD = "demo_password_123";
    String clientSecret = "demo_client_Secret_9876";
    // String ACCESS_TOKEN = "demo_commented_token_1";   (comment: not flagged)
    String awsId = "AKIAABCDEFGHIJKLMNOP";               // fictional, AWS-key-ID shaped
    void run() { System.out.println("Listening on " + PORT); }
}
