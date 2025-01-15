class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  # Validation
  validates :firstname, presence: true, uniqueness: { scope: :lastname }
  validates :email, presence: true, uniqueness: true
  validates :encrypted_password, presence: true
  has_one_attached :photo_avatar
end
