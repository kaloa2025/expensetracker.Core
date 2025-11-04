using expenseTracker.Core.Models.Auth;
using expenseTracker.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace expenseTracker.Core.Data
{
    public class CoreDbContext : DbContext
    {
        public CoreDbContext(DbContextOptions<CoreDbContext> options) : base(options) { }

        // Auth DbSets
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<OtpToken> OtpTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Apply all configurations from current assembly
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            // Global query filters for soft delete
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                if (typeof(AuditableEntity).IsAssignableFrom(entityType.ClrType))
                {
                    modelBuilder.Entity(entityType.ClrType)
                        .HasQueryFilter(GetSoftDeleteFilter(entityType.ClrType));
                }
            }
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            UpdateAuditableEntities();
            return await base.SaveChangesAsync(cancellationToken);
        }

        public override int SaveChanges()
        {
            UpdateAuditableEntities();
            return base.SaveChanges();
        }

        private void UpdateAuditableEntities()
        {
            var entries = ChangeTracker.Entries<AuditableEntity>();

            foreach (var entry in entries)
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        entry.Entity.CreatedAt = DateTime.UtcNow;
                        entry.Entity.UpdatedAt = DateTime.UtcNow;
                        // TODO: Set CreatedBy and UpdatedBy from current user context
                        break;

                    case EntityState.Modified:
                        entry.Entity.UpdatedAt = DateTime.UtcNow;
                        // TODO: Set UpdatedBy from current user context
                        break;
                }
            }
        }

        private static System.Linq.Expressions.LambdaExpression GetSoftDeleteFilter(Type entityType)
        {
            var parameter = System.Linq.Expressions.Expression.Parameter(entityType, "e");
            var property = System.Linq.Expressions.Expression.Property(parameter, "IsDeleted");
            var condition = System.Linq.Expressions.Expression.Equal(property, System.Linq.Expressions.Expression.Constant(false));
            return System.Linq.Expressions.Expression.Lambda(condition, parameter);
        }

    }
}
