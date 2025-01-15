import { Controller } from "@hotwired/stimulus"
import {toggle} from 'el-transition'

// Connects to data-controller="dropdown"
export default class extends Controller {
  static targets = ["dropdownMenu"];

  // Check if this controller has activated
  connect () {
    console.log("dropdown menu connected");
  }

  // Activate dropdown
  toggleMenu() {
    toggle(this.dropdownMenuTarget).then(() => {
      // Update Aria Expanded
      this.#toggleAriaExpanded();

      // Display transition
      console.log("Enter transition completed");
    })
  }

  // Function which update aria-expanded
  #toggleAriaExpanded() {
    const isExpanded = this.dropdownMenuTarget.classList.contains("hidden");
    this.element.setAttribute("aria-expanded", !isExpanded);
  }
}
