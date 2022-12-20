using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace AuthCSharpCorner.Data
{
    public class AuthCSharpCornerContext : IdentityDbContext<IdentityUser>
    {
        public AuthCSharpCornerContext (DbContextOptions<AuthCSharpCornerContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
