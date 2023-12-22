using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace backend.Models
{
    public class LoginCred
    {
        
            [Key]
            [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
            public int EmpCode { get; set; }

            [Required]
            public string Password { get; set; }

            [Required]
            public string Salt { get; set; }

            [Required]
            public int Algo { get; set; }

            [Required]
            public DateTime CreatedOn { get; set; }

            public DateTime ModifiedOn { get; set; }

            [Required]
            public char isactive { get; set; }

            [Required]
            public byte loginattempts { get; set; }
        
    }
}
