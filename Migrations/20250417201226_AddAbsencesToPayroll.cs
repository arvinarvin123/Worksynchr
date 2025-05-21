using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HRPayrollSystem.Migrations
{
    /// <inheritdoc />
    public partial class AddAbsencesToPayroll : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<decimal>(
                name: "Absences",
                table: "Payrolls",
                type: "decimal(18,2)",
                precision: 18,
                scale: 2,
                nullable: false,
                defaultValue: 0m);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Absences",
                table: "Payrolls");
        }
    }
}
