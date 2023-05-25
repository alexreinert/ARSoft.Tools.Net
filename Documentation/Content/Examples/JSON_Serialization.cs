// Serialize
var message = new DnsMessage()
{
	// ...
};
var json = System.Text.Json.JsonSerializer.Serialize(message, new JsonSerializerOptions() { WriteIndented = true });

// Deserialize
var msg2 = System.Text.Json.JsonSerializer.Deserialize<DnsMessage>(json);