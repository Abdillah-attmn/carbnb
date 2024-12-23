import { Controller } from "@hotwired/stimulus"

// Connects to data-controller="dropdown"
export default class extends Controller {
  static targets = ["menu"];

  toggleMenu() {
    this.menuTarget.classList.toggle("hidden");
    this.#toggleAriaExpanded();
  }

  #toggleAriaExpanded() {
    const isExpanded = this.menuTarget.classList.contains("hidden");
    this.element.setAttribute("aria-expanded", !isExpanded);
  }
}
