class Animal:
    print("INHERITENCE")
    def speak(self):
        print("Animal sound")

class Dog(Animal):
    def bark(self):
        print("Woof!")

tony = Dog()
print("break")
tony.bark()
tony.speak()
