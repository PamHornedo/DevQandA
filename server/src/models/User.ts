import { DataTypes, Model, Optional } from "sequelize";
import bcrypt from "bcrypt";
import sequelize from "../config/database";

// User attributes interface
interface UserAttributes {
  id: number;
  username: string;
  email: string;
  password: string;
  createdAt?: Date;
  updatedAt?: Date;
}

interface UserCreationAttributes extends Optional<UserAttributes, "id"> {}

// User class extending Model
class User
  extends Model<UserAttributes, UserCreationAttributes>
  implements UserAttributes
{
  // Public properties
  public id!: number;
  public username!: string;
  public email!: string;
  public password!: string;
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;
  public async comparePassword(plainPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, this.password);
  }
}

// Initialize User model
User.init(
  {
    // Model attributes
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      validate: {
        notNull: {
          msg: "Username is required",
        },
        notEmpty: {
          msg: "Username cannot be empty",
        },
        len: {
          args: [3, 20],
          msg: "Username must be within 3 and 20 characters",
        },
        isAlphanumeric: {
          msg: "Username can only contain letters and numbers",
        },
      },
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        notNull: {
          msg: "Email is required",
        },
        notEmpty: {
          msg: "Email cannot be empty",
        },
        isEmail: {
          msg: "Must be a valid email address",
        },
      },
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notNull: {
          msg: "Password is required",
        },
        notEmpty: {
          msg: "Password cannot be empty",
        },
        isStrongPassword(value: string) {
          if (value.length < 8) {
            throw new Error("Password must be at least 8 characters long");
          }
          if (!/[A-Z]/.test(value)) {
            throw new Error(
              "Password must contain at least one uppercase letter",
            );
          }
          if (!/[a-z]/.test(value)) {
            throw new Error(
              "Password must contain at least one lowercase letter",
            );
          }
          if (!/[0-9]/.test(value)) {
            throw new Error("Password must contain at least one number");
          }
        },
      },
    },
  },
  {
    sequelize,
    modelName: "User",
    tableName: "users",
    hooks: {
      async beforeCreate(user: User) {
        const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || "10");
        const hashedPassword = await bcrypt.hash(user.password, saltRounds);
        user.password = hashedPassword;

        console.log(`beforeCreate hook - password hashed`);
      },
      async beforeUpdate(user: User) {
        if (user.changed("password")) {
          const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || "10");
          const hashedPassword = await bcrypt.hash(user.password, saltRounds);
          user.password = hashedPassword;
        }
        console.log(`beforeUpdate hook - password hashed`);
      },
    },
  },
);

export default User;
