/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cs492finalproject.Interfaces;

import java.awt.Color;
import javax.swing.JTextPane;

/**
 *
 * @author JBristol
 */
public interface LogInterface {
  public void appendLog(JTextPane log, String message, Color txtColor);
}
