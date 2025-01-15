import { Controller } from "@hotwired/stimulus"

// Connects to data-controller="burger-menu"
export default class extends Controller {
  static targets = ["burger", "cross", "menu"];


  // Check if this controller has activated
  connect () {
    console.log("mobile menu connected");
  }

  toogleMobileMenu(){
    this.menuTarget.classList.toggle("hidden");
    this.#checkMenu();
    this.#toggleAriaExpanded();
  }

  #checkMenu(){
    if (this.menuTarget.classList.contains("hidden")) {
      this.burgerTarget.classList.add("block");
      this.burgerTarget.classList.remove("hidden");
      this.crossTarget.classList.add("hidden");
      this.crossTarget.classList.remove("block");

    } else {
      this.burgerTarget.classList.add("hidden");
      this.burgerTarget.classList.remove("block");
      this.crossTarget.classList.add("block");
      this.crossTarget.classList.remove("hidden");
    }
  }

  // Function which update aria-expanded
  #toggleAriaExpanded() {
    const isExpanded = this.menuTarget.classList.contains("hidden");
    this.element.setAttribute("aria-expanded", !isExpanded);
  }
}
