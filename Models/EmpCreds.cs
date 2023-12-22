// EmpCreds.cs
public class EmpCreds
{
    public int EmpCode { get; set; }

    public string? Password { get; set; }
    public string? Salt { get; set; }
    public int Algo { get; set; }
    public DateTime CreatedOn { get; set; }
    public DateTime ModifiedOn { get; set; }
    public char IsActive { get; set; }
    public byte LoginAttempts { get; set; }
}